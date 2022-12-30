-- Migration number: 0000 	 2022-12-24T23:29:53.502Z
CREATE TABLE IF NOT EXISTS login(
    Challenge  TEXT NOT NULL,
    Auth       TEXT NOT NULL PRIMARY KEY,
    KeyID TEXT NOT NULL,
    Time INT   NOT NULL 
);

CREATE TABLE IF NOT EXISTS sessions(
    SessionID   TEXT NOT NULL PRIMARY KEY,
    KeyID       TEXT NOT NULL,
    Time INT    NOT NULL 
);