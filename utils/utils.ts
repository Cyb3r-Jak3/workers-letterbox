import { Key, readKey, Message, readMessage, MaybeStream, Data } from 'openpgp';

export async function ReadKeyFromFile(
    keyFile: File
): Promise<{ key?: Key; success: boolean }> {
    let key: Key;
    try {
        key = await readKey({ armoredKey: await keyFile.text() });
        return { key, success: true };
    } catch {
        try {
            key = await readKey({
                binaryKey: new Uint8Array(await keyFile.arrayBuffer()),
            });
            return { key, success: true };
        } catch {
            return { success: false };
        }
    }
}

export async function ReadMessageFromFile(
    messageFile: File
): Promise<{ message?: Message<MaybeStream<Data>>; success: boolean }> {
    let message: Message<MaybeStream<Data>>;
    try {
        message = await readMessage({
            armoredMessage: await messageFile.text(),
        });
        return { message, success: true };
    } catch {
        try {
            message = await readMessage({
                binaryMessage: new Uint8Array(await messageFile.arrayBuffer()),
            });
            return { message, success: true };
        } catch {
            return { success: false };
        }
    }
}
