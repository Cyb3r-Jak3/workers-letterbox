import type { Context } from 'hono';
import {
    GenerateHash,
    JSONErrorResponse,
    JSONResponse,
} from '@cyb3r-jak3/common';
import { ReadMessageFromFile } from '../utils/utils';

export async function SubmitEndpoint(c: Context) {
    const req = c.req;
    if (req.headers.get('Content-Type') === null) {
        return JSONErrorResponse('Not multipart form request', 400);
    }
    const data = await req.formData();

    const letter_name = data.get('letter-name');
    if (letter_name && typeof letter_name !== 'string') {
        return JSONErrorResponse('letter name needs to be a string', 400);
    }

    const uploaded = data.get('letter');
    if (!uploaded || typeof uploaded === 'string') {
        return JSONErrorResponse(
            'Need a letter uploaded and there was none',
            400
        );
    }
    const message_copy = new File([uploaded], uploaded.name, {
        type: uploaded.type,
    });
    const { message, success } = await ReadMessageFromFile(uploaded);
    if (!success || !message) {
        return JSONErrorResponse('error reading message file', 400);
    }
    const keys = message.getEncryptionKeyIDs();
    const key_id = await GenerateHash(keys[0].toHex(), 'SHA-256');
    const file_name = `letters/${key_id}/${letter_name || crypto.randomUUID()}`;
    await c.env.R2.put(file_name, await message_copy.arrayBuffer());
    return JSONResponse('message submitted');
}
