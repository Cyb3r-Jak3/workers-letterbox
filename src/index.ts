import {
    JSONErrorResponse,
    JSONResponse,
    JSONContentHeader,
} from '@cyb3r-jak3/common';
import { Context, Hono } from 'hono';
import {
    LoginEndpoint,
    ChallengeEndpoint,
    LogoutEndpoint,
    AuthMiddleware,
} from './auth';
import { ListEndpoint, RetrieveEndpoint } from './retrieve';
import { SubmitEndpoint } from './submit';
export interface Env {
    R2: R2Bucket;
    DB: D1Database;
    Salt: string;
    LoginMinutes: number;
    GitHash: string;
    SessionMinutes?: number;
}
const app = new Hono<{ Bindings: Env }>();

app.use('*', async (c, next) => {
    try {
        await next();
        if (
            c.res.headers.get('content-type') !== JSONContentHeader &&
            c.res.status !== 404
        ) {
            console.error(
                `Got non-JSON response for ${new URL(c.req.url).pathname} - ${
                    c.res.status
                } `
            );
        }
    } catch (error) {
        console.error(
            `Uncaught error for ${new URL(c.req.url).pathname} - ${error}`
        );
        return JSONErrorResponse('unhandled server exception');
    }
});

app.post('/api/submit', SubmitEndpoint);
app.post('/api/login', LoginEndpoint);
app.post('/api/challenge', ChallengeEndpoint);

app.use('/api/logout', AuthMiddleware);
app.post('/api/logout', LogoutEndpoint);

app.use('/api/list', AuthMiddleware);
app.get('/api/list', ListEndpoint);

app.use('/api/retrieve', AuthMiddleware);
app.get('/api/retrieve', RetrieveEndpoint);

app.all('/api/version', (c: Context) => {
    return JSONResponse({ GitHash: c.env.GitHash || 'dev' });
});

export default app;
