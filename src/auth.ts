import {
    GenerateHash,
    JSONErrorResponse,
    JSONResponse,
} from '@cyb3r-jak3/common';
import { GenerateQuery, QueryType } from 'd1-orm';
import type { Context } from 'hono';
import { generateSlug } from 'random-word-slugs';
import * as openpgp from 'openpgp';

import { parse } from 'hono/utils/cookie';
import { ReadKeyFromFile } from '../utils/utils';
import { encryptData, decryptData } from '../utils/hashing';

import type { Handler } from 'hono';

export const AuthMiddleware: Handler = async (c, next) => {
    if (!c.env) {
        console.error('Hono environment is no defined.');
        return JSONErrorResponse(
            'Internal Server Error',
            undefined,
            'environment not defined'
        );
    }

    const cookie = parse(c.req.headers.get('Cookie') || '');
    const auth_cookie = cookie['l-session'];
    if (!auth_cookie) {
        return JSONErrorResponse('unauthorized', 401);
    }
    const statement = GenerateQuery(QueryType.SELECT, 'sessions', {
        where: {
            SessionID: auth_cookie,
        },
    });

    const results = await c.env.DB.prepare(statement.query)
        .bind(...statement.bindings)
        .all();

    if (!results.success) {
        console.error(`Error selecting from sessions table ${results.error}`);
        return JSONErrorResponse('Internal Server Error');
    }

    if (!results || results.results.length > 1) {
        console.error(`Got more than 1 result for auth ID: ${auth_cookie}`);
        return JSONErrorResponse('Internal Server Error');
    }
    const result = results.results[0];
    if (!result) {
        c.res = JSONErrorResponse('unauthorized', 401);
        c.cookie('l-session', '', {
            expires: new Date('1970-01-01'),
        });
        return c.res;
    }
    if (results.KeyID === '') {
        console.error('Did not KeyID for valid UUID');
        return JSONErrorResponse('Internal Server Error');
    }
    c.set('KeyID', result.KeyID);
    await next();
};

export async function LoginEndpoint(c: Context): Promise<Response> {
    const req = c.req;
    if (req.headers.get('Content-Type') === null) {
        return JSONErrorResponse('Not multipart form request', 400);
    }

    const data = await req.formData();
    const uploaded = data.get('key');
    if (!uploaded || typeof uploaded === 'string') {
        return JSONErrorResponse('Need a key and there was none', 400);
    }

    const { key, success } = await ReadKeyFromFile(uploaded);
    if (!success || !key) {
        return JSONErrorResponse('unable to read key file');
    }

    const challenge_phrase = generateSlug(30, { format: 'lower' });
    const challenge_message = await openpgp.createMessage({
        text: challenge_phrase,
    });

    const challenge_message_digest = await encryptData(
        challenge_phrase,
        c.env.Salt
    );
    const encrypted_message = openpgp.encrypt({
        message: challenge_message,
        encryptionKeys: key,
    });

    const login_uuid = crypto.randomUUID();
    const insert = GenerateQuery(QueryType.INSERT, 'login', {
        data: {
            Challenge: challenge_message_digest,
            Auth: login_uuid,
            KeyID: (await key.getEncryptionKey()).getKeyID().toHex(),
            Time: new Date().getTime(),
        },
    });
    const insert_results = await c.env.DB.prepare(insert.query)
        .bind(...insert.bindings)
        .run();
    if (!insert_results.success) {
        console.error(
            `Error inserting into login table ${insert_results.error}`
        );
        return JSONErrorResponse('DB error');
    }
    c.res = JSONResponse({ message: await encrypted_message });
    c.cookie('letterbox', login_uuid, {
        domain: new URL(c.req.url).hostname,
        maxAge: c.env.LoginMinutes * 60,
        secure: true,
        sameSite: 'Strict',
        path: '/api',
    });
    console.log('Finished Login Endpoint');
    return c.res;
}

export async function ChallengeEndpoint(c: Context): Promise<Response> {
    const req = c.req;
    if (req.headers.get('Content-Type') === null) {
        return JSONErrorResponse('Not multipart form request', 400);
    }

    const cookie = parse(c.req.headers.get('Cookie') || '');
    const login_uuid = cookie['letterbox'];
    if (!login_uuid) {
        console.log('no login cookie found');
        return JSONErrorResponse('Unauthorized', 401);
    }
    const data = await req.formData();

    const challenge = data.get('challenge')?.trim();
    if (!challenge || typeof challenge !== 'string') {
        return JSONErrorResponse('Need a challenge and there was none', 400);
    }

    const select = GenerateQuery(QueryType.SELECT, 'login', {
        where: {
            Auth: login_uuid,
        },
    });

    const select_results = await c.env.DB.prepare(select.query)
        .bind(...select.bindings)
        .all();
    if (!select_results.success) {
        console.error(
            `Error selecting from login table ${select_results.error}`
        );
        return JSONErrorResponse('DB error');
    }
    if (select_results.results.length === 0) {
        return JSONErrorResponse('unauthorized', 401);
    }
    if (select_results.results.length > 1) {
        console.log(`Got more than one result for login_uid: ${login_uuid}`);
        return JSONErrorResponse('unauthorized', 401);
    }

    const result = select_results.results[0];
    const challenge_message_digest = await decryptData(
        result.Challenge,
        c.env.Salt
    );
    const challenge_date = new Date(
        new Date(result.Time).getTime() + c.env.LOGIN_MINUTES * 60000
    );
    const current_date = new Date();

    if (challenge_date < current_date) {
        c.cookie('letterbox', '', {
            expires: new Date('1970-01-01'),
        });
        return c.text('unauthorized', 401);
    }

    if (challenge !== challenge_message_digest) {
        return c.text('unauthorized', 401);
    }

    const delete_query = GenerateQuery(QueryType.DELETE, 'login', {
        where: {
            Auth: login_uuid,
        },
    });
    const delete_results = await c.env.DB.prepare(delete_query.query)
        .bind(...delete_query.bindings)
        .run();
    if (!delete_results.success) {
        console.error(
            `Error deleting from login table ${delete_results.error}`
        );
        return JSONErrorResponse('DB error');
    }
    const session_id = crypto.randomUUID();
    const insert = GenerateQuery(QueryType.INSERT, 'sessions', {
        data: {
            SessionID: session_id,
            KeyID: await GenerateHash(result.KeyID, 'SHA-256'),
            Time: new Date().getTime(),
        },
    });

    const insert_results = await c.env.DB.prepare(insert.query)
        .bind(...insert.bindings)
        .run();
    if (!insert_results.success) {
        console.error(
            `Error inserting into sessions table ${insert_results.error}`
        );
        return JSONErrorResponse('DB error');
    }
    c.cookie('letterbox', '', {
        expires: new Date('1970-01-01'),
    });
    c.cookie('l-session', session_id, {
        domain: new URL(c.req.url).hostname,
        maxAge: c.env.LoginMinutes * 60,
        secure: true,
        sameSite: 'Strict',
        path: '/',
    });
    return c.text('logged in');
}

// LogoutEndpoint
export async function LogoutEndpoint(c: Context) {
    const keyID = c.get('KeyID');
    const delete_query = GenerateQuery(QueryType.DELETE, 'sessions', {
        where: {
            KeyID: keyID,
        },
    });
    const delete_results = await c.env.DB.prepare(delete_query.query)
        .bind(...delete_query.bindings)
        .run();
    if (!delete_results.success) {
        console.error(
            `Error deleting from session table ${delete_results.error}`
        );
        return JSONErrorResponse('DB error');
    }
    c.res = JSONResponse({ message: 'logged out' });
    c.cookie('l-session', '', {
        expires: new Date('1970-01-01'),
    });
    return c.res;
}
