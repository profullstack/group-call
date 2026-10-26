import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as signMessage } from "node:crypto";
import {
  GroupCall,
  peopleHere,
  roomCodeFrom as codeFrom,
  sameSecret,
  spokenCode,
  telnyxSms,
} from "../src/index.ts";

const CODE_LENGTH = 6;
const roomCodeFrom = (entered: unknown) => codeFrom(entered, CODE_LENGTH);

/** An ed25519 pair standing in for the account's, so a test can sign. */
function keys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return { privateKey, publicKey: raw.toString("base64") };
}

function signed(privateKey: ReturnType<typeof keys>["privateKey"], body: string, timestamp: string) {
  return signMessage(null, Buffer.from(`${timestamp}|${body}`, "utf8"), privateKey).toString("base64");
}

/** A fetch that records what Telnyx was asked and answers however a test says. */
function recorder(reply: (path: string, body: unknown) => { ok: boolean; json?: unknown } = () => ({ ok: true })) {
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  const fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const path = String(url).replace("https://api.telnyx.com/v2", "");
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
    calls.push({ path, body });
    const answer = reply(path, body);
    return {
      ok: answer.ok,
      status: answer.ok ? 200 : 422,
      text: async () => JSON.stringify(answer.json ?? {}),
    } as unknown as Response;
  }) as unknown as typeof globalThis.fetch;
  return { calls, fetch };
}

/** Telnyx answers a conference creation with its id; everything else is empty. */
const conferenceReplies = (id = "conf-1") => (path: string) =>
  path === "/conferences" ? { ok: true, json: { data: { id } } } : { ok: true };

const NOW = 1_700_000_000_000;

function line(fetch: typeof globalThis.fetch, publicKey = "", extra: Record<string, unknown> = {}) {
  return new GroupCall({ apiKey: "KEY_test", publicKey, fetch, now: () => NOW, codeLength: 6, conferencePrefix: "partyline", greeting: "Welcome to the nixamp party line. Enter the six digit room code.", ...extra });
}

/** Keying a code, as Telnyx reports it. */
const keyed = (leg: string, digits: string) => ({
  event_type: "call.gather.ended",
  payload: { call_control_id: leg, digits },
});

test("a room code is exactly six digits or it is not a code", () => {
  assert.equal(CODE_LENGTH, 6);
  assert.equal(roomCodeFrom("482917"), "482917");
  // Leading zeros survive: 048291 is a room, not the number 48291.
  assert.equal(roomCodeFrom("048291"), "048291");
  // What a keypad or a URL might wrap around it.
  assert.equal(roomCodeFrom("482-917"), "482917");
  assert.equal(roomCodeFrom(" 482 917 "), "482917");
  assert.equal(roomCodeFrom("#482917#"), "482917");
  assert.equal(roomCodeFrom(482917), "482917");

  // Five digits is a different room, not this one missing a digit. Guessing
  // which they meant would put somebody in a stranger's conversation.
  assert.equal(roomCodeFrom("48291"), "");
  assert.equal(roomCodeFrom("4829177"), "");
  assert.equal(roomCodeFrom(""), "");
  assert.equal(roomCodeFrom("abcdef"), "");
  assert.equal(roomCodeFrom(undefined), "");
  assert.equal(roomCodeFrom(null), "");
  assert.equal(roomCodeFrom({}), "");
});

test("a code is read back one digit at a time", () => {
  // "482917" spoken as a number is four hundred eighty-two thousand…, which is
  // not a code anybody can write down.
  assert.equal(spokenCode("482917"), "4, 8, 2, 9, 1, 7");
});

test("a webhook is only believed when Telnyx signed it", () => {
  const { privateKey, publicKey } = keys();
  const party = line(recorder().fetch, publicKey);
  const body = JSON.stringify({ data: { event_type: "call.answered" } });
  const ts = String(Math.floor(NOW / 1000));

  assert.equal(party.armed, true);
  assert.equal(party.verify(body, signed(privateKey, body, ts), ts), true);

  // A body edited after signing is the attack this exists to stop.
  assert.equal(party.verify(body + " ", signed(privateKey, body, ts), ts), false);
  assert.equal(party.verify(body, signed(keys().privateKey, body, ts), ts), false);
  assert.equal(party.verify(body, undefined, ts), false);
  assert.equal(party.verify(body, signed(privateKey, body, ts), undefined), false);
  assert.equal(party.verify(body, "not-base64-64-bytes", ts), false);
  assert.equal(party.verify(body, signed(privateKey, body, ts), "nonsense"), false);
});

test("a signature from too long ago is a replay, in either direction", () => {
  const { privateKey, publicKey } = keys();
  const party = line(recorder().fetch, publicKey);
  const body = JSON.stringify({ data: {} });

  const old = String(Math.floor((NOW - 10 * 60 * 1000) / 1000));
  assert.equal(party.verify(body, signed(privateKey, body, old), old), false);

  const ahead = String(Math.floor((NOW + 10 * 60 * 1000) / 1000));
  assert.equal(party.verify(body, signed(privateKey, body, ahead), ahead), false);

  const fresh = String(Math.floor((NOW - 60 * 1000) / 1000));
  assert.equal(party.verify(body, signed(privateKey, body, fresh), fresh), true);
});

test("without a public key nothing is believed", () => {
  const party = line(recorder().fetch, "");
  assert.equal(party.armed, false);
  assert.equal(party.verify("{}", "x", "1"), false);
  assert.equal(line(recorder().fetch, Buffer.alloc(16).toString("base64")).armed, false);
});

test("an inbound call is answered and asked for a code, on the keypad", async () => {
  const { calls, fetch } = recorder();
  const party = line(fetch);

  await party.handle({
    event_type: "call.initiated",
    payload: { call_control_id: "leg-1", direction: "incoming" },
  });
  assert.deepEqual(calls.map((c) => c.path), ["/calls/leg-1/actions/answer"]);

  await party.handle({ event_type: "call.answered", payload: { call_control_id: "leg-1" } });
  const ask = calls[1];
  // The keypad, not speech. One digit misheard is a different room that also
  // exists, and nothing would tell the caller they went wrong.
  assert.equal(ask?.path, "/calls/leg-1/actions/gather_using_speak");
  assert.equal(ask?.body["minimum_digits"], 6);
  assert.equal(ask?.body["maximum_digits"], 6);
  assert.equal(ask?.body["valid_digits"], "0123456789");
  assert.match(String(ask?.body["payload"]), /six digit/i);
  assert.ok(!calls.some((c) => c.path.endsWith("gather_using_ai")));
});

test("an outbound leg is not somebody calling in", async () => {
  const { calls, fetch } = recorder();
  await line(fetch).handle({
    event_type: "call.initiated",
    payload: { call_control_id: "leg-1", direction: "outgoing" },
  });
  assert.deepEqual(calls, []);
});

test("the first caller opens the room and the second lands in it", async () => {
  const { calls, fetch } = recorder(conferenceReplies("conf-482917"));
  const party = line(fetch);

  await party.handle(keyed("leg-1", "482917"));
  const created = calls.find((c) => c.path === "/conferences");
  assert.ok(created, "the first caller creates the conference");
  assert.equal(created?.body["call_control_id"], "leg-1");
  assert.deepEqual(party.list(), [{ code: "482917", callers: 1, startedAt: NOW }]);

  await party.handle(keyed("leg-2", "482917"));
  assert.ok(
    calls.some(
      (c) => c.path === "/conferences/conf-482917/actions/join" && c.body["call_control_id"] === "leg-2",
    ),
    "the second caller joins rather than opening a second room",
  );
  assert.equal(calls.filter((c) => c.path === "/conferences").length, 1);
  assert.equal(party.list()[0]?.callers, 2);
});

test("a line is read into a room only while somebody is on the phone in it, in the voice asked for", async () => {
  const { calls, fetch } = recorder(conferenceReplies("conf-482917"));
  const party = line(fetch);
  // Nobody has called: nothing to read to, and Telnyx is not asked.
  assert.equal(party.hasCallers("482917"), false);
  assert.equal(await party.say("482917", "chovy says: hello", "Telnyx.KokoroTTS.am_adam"), false);
  assert.equal(calls.filter((c) => c.path.endsWith("/actions/speak")).length, 0);

  await party.handle(keyed("leg-1", "482917"));
  assert.equal(party.hasCallers("482917"), true);
  const before = calls.filter((c) => c.path.endsWith("/actions/speak")).length;
  assert.equal(await party.say("482917", "  chovy says:   hello   room  ", "Telnyx.KokoroTTS.am_adam"), true);
  const spoken = calls.filter((c) => c.path === "/conferences/conf-482917/actions/speak").slice(before);
  const said = spoken.find((c) => c.body["payload"] === "chovy says: hello room");
  assert.ok(said, "the line is spoken into the conference, tidied");
  assert.equal(said?.body["voice"], "Telnyx.KokoroTTS.am_adam");
  // To the whole room, not one leg: a trollbox line is for everybody there.
  assert.equal(said?.body["call_control_ids"], undefined);
  assert.equal(said?.body["voice_settings"], undefined);
  // An ElevenLabs voice carries the name of the secret Telnyx holds the key under.
  await party.say("482917", "chovy says: again", "ElevenLabs.pNInz6obpgDQGcFmaJgB", { api_key_ref: "elevenlabs" });
  const eleven = calls.filter((c) => c.path === "/conferences/conf-482917/actions/speak").pop();
  assert.deepEqual(eleven?.body["voice_settings"], { api_key_ref: "elevenlabs" });
  assert.equal(eleven?.body["voice"], "ElevenLabs.pNInz6obpgDQGcFmaJgB");
  // An empty line is not worth a call.
  assert.equal(await party.say("482917", "   ", "female"), false);
  // No voice given: the room's own.
  await party.say("482917", "again", "");
  const last = calls.filter((c) => c.path === "/conferences/conf-482917/actions/speak").pop();
  assert.equal(typeof last?.body["voice"], "string");
  assert.notEqual(last?.body["voice"], "");
});

test("the listing publishes the code, because a listing you cannot dial is nothing", async () => {
  const { calls, fetch } = recorder(conferenceReplies());
  const party = line(fetch);
  await party.handle(keyed("leg-1", "482917"));

  // This is a public call-in line, not a private room. The code is how you
  // join, so withholding it would leave a list nobody can act on.
  assert.deepEqual(Object.keys(party.list()[0] ?? {}).sort(), ["callers", "code", "startedAt"]);
  assert.equal(party.list()[0]?.code, "482917");

  // Still not the Telnyx conference name, which is a different concern: that
  // is a label in somebody else's dashboard, and it should not be load-bearing.
  const created = calls.find((c) => c.path === "/conferences");
  assert.ok(!String(created?.body["name"]).includes("482917"));
});

test("two codes are two rooms", async () => {
  let n = 0;
  const { fetch } = recorder((path) =>
    path === "/conferences" ? { ok: true, json: { data: { id: `conf-${++n}` } } } : { ok: true },
  );
  const party = line(fetch);

  await party.handle(keyed("a", "111111"));
  await party.handle(keyed("b", "222222"));
  assert.deepEqual(party.list().map((r) => r.callers), [1, 1]);
});

test("a code that is not six digits is re-asked, never guessed at", async () => {
  const { calls, fetch } = recorder();
  const party = line(fetch);

  await party.handle({ event_type: "call.answered", payload: { call_control_id: "leg-1" } });
  await party.handle(keyed("leg-1", "4829"));

  const reask = calls.filter((c) => c.path === "/calls/leg-1/actions/gather_using_speak")[1];
  assert.ok(reask, "it asks again");
  // It says how many it got: a caller whose sixth digit was lost in the tone
  // over the prompt is told so, rather than left to wonder if the line works.
  assert.match(String(reask?.body["payload"]), /I only got 4 digits/);
  // The re-ask does not repeat the welcome; that is the "repeats itself".
  assert.doesNotMatch(String(reask?.body["payload"]), /Welcome/);
  // And it stops waiting for a digit that is not coming.
  assert.equal(reask?.body["inter_digit_timeout_millis"], 4000);
  // Nothing was opened on a code we could not read.
  assert.equal(calls.filter((c) => c.path === "/conferences").length, 0);
  assert.deepEqual(party.list(), []);
});

test("a gather that ended with nothing is asked again without a scolding", async () => {
  const { calls, fetch } = recorder();
  const party = line(fetch);

  await party.handle(keyed("leg-1", ""));

  const reask = calls.find((c) => c.path === "/calls/leg-1/actions/gather_using_speak");
  assert.match(String(reask?.body["payload"]), /did not get a code/i);
  assert.doesNotMatch(String(reask?.body["payload"]), /only got/);
});

test("a gather that ended because the caller hung up is not answered", async () => {
  // Anything sent to that leg now is a 422, which is what the log showed.
  const { calls, fetch } = recorder();
  const party = line(fetch);

  await party.handle({
    event_type: "call.gather.ended",
    payload: { call_control_id: "leg-1", digits: "", status: "call_hangup" },
  });

  assert.deepEqual(calls, []);
});

test("three empty gathers is goodbye, not a fourth prompt", async () => {
  // A voice that fails, or a keypad that sends nothing, made a line that
  // asked for a code every ninety seconds until the caller gave up.
  const { calls, fetch } = recorder();
  const party = line(fetch);

  await party.handle({ event_type: "call.answered", payload: { call_control_id: "leg-1" } });
  await party.handle(keyed("leg-1", ""));
  await party.handle(keyed("leg-1", ""));
  assert.equal(calls.filter((c) => c.path === "/calls/leg-1/actions/gather_using_speak").length, 3);
  assert.equal(calls.filter((c) => c.path === "/calls/leg-1/actions/hangup").length, 0);

  await party.handle(keyed("leg-1", ""));
  assert.equal(calls.filter((c) => c.path === "/calls/leg-1/actions/gather_using_speak").length, 3);
  const bye = calls.find((c) => c.path === "/calls/leg-1/actions/speak");
  assert.match(String(bye?.body["payload"]), /Goodbye/);
  assert.equal(calls.filter((c) => c.path === "/calls/leg-1/actions/hangup").length, 1);
});

test("when the voice fails, the leg hears the plain one from then on", async () => {
  // Telnyx's Kokoro voice answered a prompt with a 500; the gather it belonged
  // to ended at once with no digits. Asking again in the same voice is asking
  // for the same silence.
  const { calls, fetch } = recorder();
  const party = line(fetch);

  await party.handle({ event_type: "call.answered", payload: { call_control_id: "leg-1" } });
  assert.equal(calls[0]?.body["voice"], "Telnyx.KokoroTTS.af");

  await party.handle({ event_type: "call.speak.failed", payload: { call_control_id: "leg-1" } });
  await party.handle(keyed("leg-1", ""));
  const reask = calls[1];
  assert.equal(reask?.path, "/calls/leg-1/actions/gather_using_speak");
  assert.equal(reask?.body["voice"], "female");

  // Another caller's voice is not touched by this one's failure.
  await party.handle({ event_type: "call.answered", payload: { call_control_id: "leg-2" } });
  assert.equal(calls[2]?.body["voice"], "Telnyx.KokoroTTS.af");
});

test("a caller is welcomed once they are in the room, and told how many are there", async () => {
  const { calls, fetch } = recorder(conferenceReplies("conf-482917"));
  const party = line(fetch);

  await party.handle(keyed("leg-1", "482917"));
  // Spoken into the conference, to that participant, after the conference
  // exists: a speak on the leg before the join was cut off by the join.
  const paths = calls.map((c) => c.path);
  assert.ok(paths.indexOf("/conferences") < paths.indexOf("/conferences/conf-482917/actions/speak"));
  const first = calls.find((c) => c.path === "/conferences/conf-482917/actions/speak");
  assert.deepEqual(first?.body["call_control_ids"], ["leg-1"]);
  assert.match(String(first?.body["payload"]), /Welcome to room 4, 8, 2, 9, 1, 7/);
  assert.match(String(first?.body["payload"]), /You are the first one here/);
  assert.equal(calls.filter((c) => c.path === "/calls/leg-1/actions/speak").length, 0);

  await party.handle(keyed("leg-2", "482917"));
  const second = calls.filter((c) => c.path === "/conferences/conf-482917/actions/speak")[1];
  assert.deepEqual(second?.body["call_control_ids"], ["leg-2"]);
  assert.match(String(second?.body["payload"]), /There is one other person in here/);

  await party.handle(keyed("leg-3", "482917"));
  const third = calls.filter((c) => c.path === "/conferences/conf-482917/actions/speak")[2];
  assert.match(String(third?.body["payload"]), /There are 3 people in here/);
});

test("who is in a room is said in words a caller can act on", () => {
  assert.match(peopleHere(0), /first one here/);
  assert.match(peopleHere(1), /first one here/);
  assert.match(peopleHere(2), /one other person/);
  assert.match(peopleHere(5), /5 people in here/);
});

test("hanging up empties the room, and an empty room stops existing", async () => {
  const { fetch } = recorder(conferenceReplies());
  const party = line(fetch);

  await party.handle(keyed("leg-1", "482917"));
  await party.handle(keyed("leg-2", "482917"));
  assert.equal(party.list()[0]?.callers, 2);

  await party.handle({ event_type: "call.hangup", payload: { call_control_id: "leg-2" } });
  assert.equal(party.list()[0]?.callers, 1);

  await party.handle({ event_type: "conference.participant.left", payload: { call_control_id: "leg-1" } });
  assert.deepEqual(party.list(), []);

  // A leg we never placed is not an error.
  await party.handle({ event_type: "call.hangup", payload: { call_control_id: "never-seen" } });
  assert.deepEqual(party.list(), []);
});

test("the same leg twice is still one caller", async () => {
  const { fetch } = recorder(conferenceReplies());
  const party = line(fetch);
  await party.handle(keyed("leg-1", "482917"));
  await party.handle(keyed("leg-1", "482917"));
  assert.equal(party.list()[0]?.callers, 1);
});

test("a full room turns a caller away rather than billing for them", async () => {
  const { calls, fetch } = recorder(conferenceReplies());
  const party = line(fetch, "", { maxParticipants: 1 });

  await party.handle(keyed("leg-1", "482917"));
  await party.handle(keyed("leg-2", "482917"));

  assert.equal(party.list()[0]?.callers, 1);
  assert.ok(calls.some((c) => c.path === "/calls/leg-2/actions/hangup"));
  assert.ok(calls.some((c) => c.path === "/conferences" && c.body["max_participants"] === 1));
});

test("a conference Telnyx has already discarded is remade, not joined forever", async () => {
  let n = 0;
  const { calls, fetch } = recorder((path) =>
    path === "/conferences"
      ? { ok: true, json: { data: { id: `conf-${++n}` } } }
      : { ok: !path.includes("/actions/join") },
  );
  const party = line(fetch);

  await party.handle(keyed("leg-1", "482917"));
  await party.handle(keyed("leg-2", "482917"));

  assert.ok(calls.some((c) => c.path === "/conferences/conf-1/actions/join"));
  assert.equal(calls.filter((c) => c.path === "/conferences").length, 2);
  assert.equal(party.list()[0]?.callers, 2);
});

test("a caller is not left on a silent line when the room cannot be opened", async () => {
  const { calls, fetch } = recorder((path) => ({ ok: path !== "/conferences" }));
  const party = line(fetch);

  await party.handle(keyed("leg-1", "482917"));

  assert.ok(calls.some((c) => c.path === "/calls/leg-1/actions/speak"));
  assert.ok(calls.some((c) => c.path === "/calls/leg-1/actions/hangup"));
  assert.deepEqual(party.list(), []);
});

test("an event without a leg, or of a kind we do not run, does nothing", async () => {
  const { calls, fetch } = recorder();
  const party = line(fetch);
  await party.handle({ event_type: "call.answered", payload: {} });
  await party.handle({ event_type: "call.machine.detection.ended", payload: { call_control_id: "leg-1" } });
  await party.handle({});
  assert.deepEqual(calls, []);
});

test("a secret is compared without leaking how much of it matched", () => {
  assert.equal(sameSecret("abc", "abc"), true);
  assert.equal(sameSecret("abc", "abd"), false);
  assert.equal(sameSecret("abc", "abcd"), false);
  assert.equal(sameSecret("", ""), true);
});


// --- the phone line as a way into a stream ---------------------------------

/** 9:27 PM Pacific, the time in the line this was built to say. */
const NINE_TWENTY_SEVEN = 1_788_928_020_000;

/** A directory of exactly the streams a test describes. */
function streams(
  live: Record<string, { name: string; url: string; audio: string; nowPlaying: string; startedAt: number }> = {},
  ended: Record<string, { name: string; nowPlaying: string; startedAt: number; endedAt: number }> = {},
) {
  return {
    liveByCode: (code: string) => live[code],
    endedByCode: (code: string) => ended[code],
  };
}

/** An SMS gateway that keeps what it was asked to send. */
function texter(ok = true) {
  const sent: { to: string; text: string }[] = [];
  return { sent, send: async (to: string, text: string) => (sent.push({ to, text }), ok) };
}

const called = (leg: string, from: string) => ({
  event_type: "call.initiated",
  payload: { call_control_id: leg, direction: "incoming", from },
});

test("a text is sent from the number that can send one", async () => {
  const { calls, fetch } = recorder();
  const sms = telnyxSms({ apiKey: "KEY_test", from: "+14084269127", fetch });
  assert.equal(await sms.send("+14155550123", "hello"), true);

  const sent = calls[0];
  assert.equal(sent?.path, "/messages");
  // Not the toll-free line the call came in on: unverified toll-free A2P is
  // filtered by carriers.
  assert.equal(sent?.body["from"], "+14084269127");
  assert.equal(sent?.body["to"], "+14155550123");
});

test("a text that will not send is reported as not sent", async () => {
  const { fetch } = recorder(() => ({ ok: false }));
  const sms = telnyxSms({ apiKey: "KEY_test", from: "+14084269127", fetch });
  assert.equal(await sms.send("+14155550123", "hello"), false);
});

// --- what the package adds over nixamp's party line --------------------------

function four(fetch: typeof globalThis.fetch, extra: Record<string, unknown> = {}) {
  return new GroupCall({ apiKey: "KEY_test", publicKey: "", fetch, now: () => NOW, codeLength: 4, ...extra });
}

test("a four-digit line asks for four digits, and says so", async () => {
  const { calls, fetch } = recorder();
  const call = four(fetch);
  await call.handle({ event_type: "call.answered", payload: { call_control_id: "leg-1" } });
  const gather = calls.find((one) => one.path.endsWith("/gather_using_speak"));
  assert.equal(gather?.body["minimum_digits"], 4);
  assert.equal(gather?.body["maximum_digits"], 4);
  assert.match(String(gather?.body["payload"]), /four digit room code/);
});

test("a code the app does not know is refused and asked again, not opened", async () => {
  const { calls, fetch } = recorder(conferenceReplies());
  const call = four(fetch, { onCode: (code: string) => (code === "4821" ? true : { reject: "That is not a room." }) });
  await call.handle({ event_type: "call.answered", payload: { call_control_id: "leg-1" } });
  calls.length = 0;
  await call.handle(keyed("leg-1", "9999"));
  assert.equal(calls.some((one) => one.path === "/conferences"), false);
  const asked = calls.find((one) => one.path.endsWith("/gather_using_speak"));
  assert.match(String(asked?.body["payload"]), /^That is not a room\. Enter the four digit room code\./);
  await call.handle(keyed("leg-1", "4821"));
  assert.equal(calls.some((one) => one.path === "/conferences"), true);
  assert.equal(call.callersIn("4821"), 1);
});

test("guessing codes runs out like any other wrong answer", async () => {
  const { calls, fetch } = recorder();
  const call = four(fetch, { onCode: () => ({ reject: "No." }) });
  await call.handle({ event_type: "call.answered", payload: { call_control_id: "leg-1" } });
  for (const digits of ["1111", "2222", "3333"]) await call.handle(keyed("leg-1", digits));
  assert.equal(calls.at(-1)?.path, "/calls/leg-1/actions/hangup");
});

test("an app can ask its own question and get the answer back", async () => {
  const { calls, fetch } = recorder();
  const answers: string[] = [];
  const call = four(fetch, {
    onCode: async (_code: string, caller: import("../src/index.ts").CallHandle) => {
      await caller.gather("Press 1 for a text.", { validDigits: "1" }, async (digits) => {
        answers.push(digits);
        await caller.goodbye("Bye.");
      });
      return "handled" as const;
    },
  });
  await call.handle(keyed("leg-1", "4821"));
  await call.handle(keyed("leg-1", "1"));
  assert.deepEqual(answers, ["1"]);
  assert.equal(calls.at(-1)?.path, "/calls/leg-1/actions/hangup");
  assert.equal(calls.some((one) => one.path === "/conferences"), false);
});

test("an agent that said who it is joins under its name; a stranger from elsewhere does not get it", async () => {
  const { fetch } = recorder(conferenceReplies());
  const joined: { code: string; name: string }[] = [];
  const call = four(fetch, { onJoin: (code: string, who: { name: string }) => joined.push({ code, name: who.name }) });
  call.expect("4821", "+1 (949) 284-7328", "riotcoder");
  await call.handle({ event_type: "call.initiated", payload: { call_control_id: "leg-a", direction: "incoming", from: "+15550001111" } });
  await call.handle(keyed("leg-a", "4821"));
  await call.handle({ event_type: "call.initiated", payload: { call_control_id: "leg-b", direction: "incoming", from: "+19492847328" } });
  await call.handle(keyed("leg-b", "4821"));
  assert.deepEqual(joined, [{ code: "4821", name: "" }, { code: "4821", name: "riotcoder" }]);
  assert.deepEqual(call.participants("4821").map((one) => one.name), ["", "riotcoder"]);
});

test("an expected name is only for its own room", async () => {
  const { fetch } = recorder(conferenceReplies());
  const call = four(fetch);
  call.expect("4821", "+19492847328", "riotcoder");
  await call.handle({ event_type: "call.initiated", payload: { call_control_id: "leg-b", direction: "incoming", from: "+19492847328" } });
  await call.handle(keyed("leg-b", "7310"));
  assert.equal(call.participants("7310")[0]?.name, "");
});

test("leaving is reported with who left and how many are still there", async () => {
  const { fetch } = recorder(conferenceReplies());
  const left: { code: string; callers: number }[] = [];
  const call = four(fetch, { onLeave: (code: string, _who: unknown, room: { callers: number }) => left.push({ code, callers: room.callers }) });
  await call.handle(keyed("leg-1", "4821"));
  await call.handle(keyed("leg-2", "4821"));
  await call.handle({ event_type: "call.hangup", payload: { call_control_id: "leg-1" } });
  assert.deepEqual(left, [{ code: "4821", callers: 1 }]);
});

test("an ElevenLabs voice carries its settings, and the fallback does not", async () => {
  const { calls, fetch } = recorder();
  const call = four(fetch, { voice: "ElevenLabs.Default.abc", voiceSettings: { api_key_ref: "k" } });
  await call.handle({ event_type: "call.answered", payload: { call_control_id: "leg-1" } });
  assert.deepEqual(calls.at(-1)?.body["voice_settings"], { api_key_ref: "k" });
  await call.handle({ event_type: "call.speak.failed", payload: { call_control_id: "leg-1" } });
  await call.handle(keyed("leg-1", ""));
  assert.equal(calls.at(-1)?.body["voice"], "female");
  assert.equal(calls.at(-1)?.body["voice_settings"], undefined);
});

test("a new room code is never an easy one and never a taken one", async () => {
  const { newRoomCode } = await import("../src/index.ts");
  const seq = [0.1, 0.1, 0.1, 0.1, 0.1, 0.2, 0.3, 0.4, 0.4, 0.7, 0.2, 0.9];
  let i = 0;
  const random = () => seq[i++ % seq.length]!;
  const code = newRoomCode(4, () => false, random);
  assert.equal(code, "4729");
  assert.notEqual(code, "1111");
  assert.notEqual(code, "1234");
  const taken = new Set(["5678"]);
  assert.equal(taken.has(newRoomCode(4, (c) => taken.has(c))), false);
});

test("with transcribe on, each participant's own leg is transcribed and lines come back with the speaker", async () => {
  const { calls, fetch } = recorder(conferenceReplies());
  const lines: string[] = [];
  const call = four(fetch, { transcribe: true, onTranscript: (code: string, who: { name: string; from: string }, text: string) => lines.push(`${code} ${who.name || who.from}: ${text}`) });
  call.expect("4821", "+19492847328", "riotcoder");
  await call.handle({ event_type: "call.initiated", payload: { call_control_id: "leg-a", direction: "incoming", from: "+19492847328" } });
  await call.handle(keyed("leg-a", "4821"));
  const start = calls.find((c) => c.path === "/calls/leg-a/actions/transcription_start");
  assert.equal(start?.body["transcription_tracks"], "inbound");
  await call.handle({ event_type: "call.transcription", payload: { call_control_id: "leg-a", transcription_data: { transcript: "hello there", is_final: false } } });
  await call.handle({ event_type: "call.transcription", payload: { call_control_id: "leg-a", transcription_data: { transcript: " Hi everyone. ", is_final: true } } });
  // A leg that is in no room is nobody's line.
  await call.handle({ event_type: "call.transcription", payload: { call_control_id: "leg-z", transcription_data: { transcript: "stray", is_final: true } } });
  assert.deepEqual(lines, ["4821 riotcoder: Hi everyone."]);
});

test("without transcribe, nothing is transcribed", async () => {
  const { calls, fetch } = recorder(conferenceReplies());
  const call = four(fetch);
  await call.handle(keyed("leg-a", "4821"));
  assert.equal(calls.some((c) => c.path.endsWith("/transcription_start")), false);
});

test("after a restart, a caller joins the room's running conference, not a new one", async () => {
  const calls: { method: string; path: string }[] = [];
  let name = "";
  const fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const path = String(url).replace("https://api.telnyx.com/v2", "");
    const method = init?.method ?? "GET";
    calls.push({ method, path });
    if (method === "POST" && path === "/conferences") {
      name = JSON.parse(String(init?.body)).name;
      return new Response(JSON.stringify({ data: { id: "conf-old" } }));
    }
    if (method === "GET" && path.startsWith("/conferences?")) return new Response(JSON.stringify({ data: [{ id: "conf-old", name, created_at: new Date(NOW).toISOString() }] }));
    if (method === "GET" && path.includes("/participants")) return new Response(JSON.stringify({ data: [{ call_control_id: "leg-1", status: "joined" }] }));
    return new Response("{}");
  }) as unknown as typeof globalThis.fetch;
  const before = four(fetch);
  await before.handle(keyed("leg-1", "4821"));
  assert.ok(name && !name.includes("4821"), "the name hides the code");
  const after = four(fetch); // a new process: empty map
  await after.handle(keyed("leg-2", "4821"));
  assert.equal(calls.filter((c) => c.method === "POST" && c.path === "/conferences").length, 1);
  assert.ok(calls.some((c) => c.path === "/conferences/conf-old/actions/join"));
  assert.equal(after.callersIn("4821"), 2);
});

test("a new process restores saved rooms that are still running, names and all, and drops the ones that ended", async () => {
  const fetch = (async (url: string | URL | Request) => {
    const path = String(url).replace("https://api.telnyx.com/v2", "");
    if (path === "/conferences/conf-live") return new Response(JSON.stringify({ data: { id: "conf-live", status: "in_progress" } }));
    if (path === "/conferences/conf-done") return new Response(JSON.stringify({ data: { id: "conf-done", status: "completed" } }));
    if (path.startsWith("/conferences/conf-live/participants")) return new Response(JSON.stringify({ data: [{ call_control_id: "leg-a", status: "joined" }, { call_control_id: "leg-b", status: "joined" }] }));
    return new Response("{}");
  }) as unknown as typeof globalThis.fetch;
  const lines: string[] = [];
  const call = four(fetch, { transcribe: true, onTranscript: (_c: string, who: { name: string }, text: string) => lines.push(`${who.name}: ${text}`) });
  const r = await call.restore([
    { code: "4821", conferenceId: "conf-live", startedAt: NOW - 60_000, participants: [{ leg: "leg-a", from: "+19492847328", name: "riotcoder", joinedAt: NOW - 50_000 }, { leg: "leg-gone", from: "+1555", name: "", joinedAt: NOW - 40_000 }] },
    { code: "7310", conferenceId: "conf-done", startedAt: NOW - 60_000, participants: [] },
  ]);
  assert.deepEqual(r, { rooms: 1, legs: 2 });
  assert.equal(call.callersIn("4821"), 2);
  assert.equal(call.callersIn("7310"), 0);
  assert.deepEqual(call.participants("4821").map((p) => p.name).sort(), ["", "riotcoder"]);
  // Its transcript keeps flowing under the right name.
  await call.handle({ event_type: "call.transcription", payload: { call_control_id: "leg-a", transcription_data: { transcript: "still here", is_final: true } } });
  assert.deepEqual(lines, ["riotcoder: still here"]);
});

test("dial rings a phone from the room's number, and the answer is asked to press 1 before it joins", async () => {
  const { calls, fetch } = recorder((path) => (path === "/calls" ? { ok: true, json: { data: { call_control_id: "out-1" } } } : conferenceReplies()(path)));
  const party = line(fetch);
  const placed = await party.dial("482913", "(408) 555-0101", { from: "+15106169327", connectionId: "conn-1", name: "Anthony", prompt: "Calling you into Standup." });
  assert.deepEqual(placed, { leg: "out-1" });
  const call = calls.find((c) => c.path === "/calls")!;
  assert.equal(call.body["to"], "+14085550101");
  assert.equal(call.body["from"], "+15106169327");
  assert.equal(call.body["connection_id"], "conn-1");

  await party.handle({ event_type: "call.answered", payload: { call_control_id: "out-1", direction: "outgoing" } });
  const ask = calls.at(-1)!;
  assert.match(ask.path, /out-1\/actions\/gather_using_speak$/);
  assert.match(String(ask.body["payload"]), /Calling you into Standup\. Press 1 to join\./);
  assert.equal(party.callersIn("482913"), 0);

  await party.handle(keyed("out-1", "1"));
  assert.equal(party.callersIn("482913"), 1);
  assert.equal(party.participants("482913")[0]!.name, "Anthony");
  assert.equal(party.participants("482913")[0]!.from, "+14085550101");
});

test("a dialled phone that does not press 1 is let go, never put in the room", async () => {
  const { calls, fetch } = recorder((path) => (path === "/calls" ? { ok: true, json: { data: { call_control_id: "out-2" } } } : { ok: true }));
  const party = line(fetch);
  await party.dial("482913", "+14085550101", { from: "+15106169327", connectionId: "conn-1" });
  await party.handle({ event_type: "call.answered", payload: { call_control_id: "out-2", direction: "outgoing" } });
  assert.equal(calls.at(-1)!.body["valid_digits"], "1");
  await party.handle(keyed("out-2", ""));
  assert.match(calls.at(-1)!.path, /out-2\/actions\/hangup$/);
  assert.equal(party.callersIn("482913"), 0);
});

test("a dialled answer that arrives after a restart still knows its room, from client_state", async () => {
  const { calls, fetch } = recorder(conferenceReplies());
  const party = line(fetch);
  const state = Buffer.from(JSON.stringify({ gc: "dial", code: "482913" })).toString("base64");
  await party.handle({ event_type: "call.answered", payload: { call_control_id: "out-3", direction: "outgoing", client_state: state } });
  assert.match(calls.at(-1)!.path, /out-3\/actions\/gather_using_speak$/);
  await party.handle(keyed("out-3", "1"));
  assert.equal(party.callersIn("482913"), 1);
});

test("an outbound leg somebody else placed is still left alone, client_state or not", async () => {
  const { calls, fetch } = recorder();
  const party = line(fetch);
  await party.handle({ event_type: "call.answered", payload: { call_control_id: "x", direction: "outgoing", client_state: Buffer.from("{\"other\":1}").toString("base64") } });
  assert.equal(calls.length, 0);
});

test("dial refuses a call it cannot place", async () => {
  const { fetch } = recorder(() => ({ ok: false }));
  const party = line(fetch);
  assert.equal(await party.dial("482913", "+14085550101", { from: "+15106169327", connectionId: "conn-1" }), null);
  assert.equal(await party.dial("482913", "nope", { from: "+15106169327", connectionId: "conn-1" }), null);
});
