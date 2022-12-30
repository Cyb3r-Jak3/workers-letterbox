import { JSONErrorResponse, JSONResponse } from '@cyb3r-jak3/common';
import type { Context } from 'hono';

export async function ListEndpoint(c: Context) {
    const keyID = c.get('KeyID');
    const messagePrefix = `letters/${keyID}`;
    const list_options = {
        prefix: messagePrefix,
    };
    const messages: R2Objects = await c.env.R2.list(list_options);
    let truncated = messages.truncated;
    let cursor = truncated ? messages.cursor : undefined;
    while (truncated) {
        const next = await c.env.R2.list({
            ...list_options,
            cursor: cursor,
        });
        messages.objects.push(...next.objects);

        truncated = next.truncated;
        cursor = next.cursor;
    }
    const messageName: string[] = [];
    for (const object of messages.objects) {
        messageName.push(object.key.replace(`${messagePrefix}/`, ''));
    }
    return JSONResponse({ count: messages.objects.length, name: messageName });
}

export async function RetrieveEndpoint(c: Context): Promise<Response> {
    const keyID = c.get('KeyID');
    const { letter_name } = c.req.query();
    const message_name = `letters/${keyID}/${letter_name}`;
    const message: R2ObjectBody | null = await c.env.R2.get(message_name);
    if (!message) {
        return JSONErrorResponse('letter not found', 404);
    }
    c.executionCtx.waitUntil(c.env.R2.delete(message_name));
    return new Response(await message.blob());
}
