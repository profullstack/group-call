# @profullstack/group-call

A group call on a phone number. People dial in, key a room code, and talk with
everyone else who keyed the same code. AI agents phone in the same way, keying the
code with DTMF, so a room holds both.

It's the engine behind [nixamp](https://nixamp.com)'s live-join party line and
[group.call.pit.world](https://group.call.pit.world). Audio mixing is Telnyx's. This
package answers Telnyx Call Control webhooks and runs the state machine: answer, ask
for the code on the keypad, join or create the conference, welcome the caller, count
who is there.

```sh
npm i @profullstack/group-call
```

```ts
import { GroupCall } from "@profullstack/group-call";

const line = new GroupCall({
  apiKey: process.env.TELNYX_API_KEY!,
  publicKey: process.env.TELNYX_PUBLIC_KEY!, // the account's ed25519 key, base64
  codeLength: 4,
  greeting: "Welcome to group call. Enter the four digit room code.",
  // Only rooms you know about open. Leave this out and any code is a room.
  onCode: (code) => (rooms.has(code) ? { welcome: `Welcome to ${rooms.get(code)}. ` } : { reject: "That is not a room." }),
  onJoin: (code, who) => console.log(`${who.name || who.from} joined ${code}`),
  onLeave: (code, who) => console.log(`${who.name || who.from} left ${code}`),
});

// Your webhook route. Check the signature against the raw body, then hand over the event.
if (!line.verify(rawBody, headers["telnyx-signature-ed25519"], headers["telnyx-timestamp"])) return 401;
await line.handle(JSON.parse(rawBody).data);
```

## What it does

- **Keypad codes only.** A misheard spoken digit is a different room that also exists.
  It asks three times, says how many digits it got, then says goodbye.
- **Conferences that outlive Telnyx's 4-hour expiry.** A stale id is remade on the next join.
- **A fallback voice.** If the main voice fails once, that leg hears the plain voice from
  then on, so a broken TTS voice can't loop silently.
- **ElevenLabs voices** with `voiceSettings: { api_key_ref }`.
- **Agents with names.** `line.expect(code, callerId, "riotcoder")` before an agent dials
  in, and the room knows who it is.
- **Room API.** `say(code, text, voice?)` speaks into a room. Also `participants(code)`,
  `kick(code, leg)`, `list()`, `hasCallers(code)` and `callersIn(code)`.
- **App hooks.** `onCode` can join, welcome, reject, or take the call over: `call.gather(...)`
  asks another question (nixamp's "press 1 for a text").
- **Live transcripts.** With `transcribe: true`, each participant's own leg is transcribed, and
  `onTranscript(code, who, text)` gets every finished line with its speaker, agents included.
  Telnyx bills this per minute per leg, so it's off unless you ask for it.
- **Survives restarts.** Conference names carry a keyed hash of the room code. After a restart,
  the first caller into a room joins its running conference, not a new one.
- `telnyxSms`, `verifyTelnyx`, `newRoomCode`, `sameSecret` helpers.

MIT
