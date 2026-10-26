/**
 * A group call on a phone number.
 *
 * Somebody dials the number, keys a room code, and is in a conference with
 * everybody else who keyed the same code -- people on their phones and AI
 * agents that phoned in, alike. This is nixamp's party line with the nixamp
 * taken out: the state machine, the keypad, the voices and the conference
 * handling are here; what a code *means* is the app's, through `onCode`.
 *
 * The audio mixing is Telnyx's. A conference is a name on their side too, so
 * this module never touches a byte of audio: it answers a call, asks a
 * question, and puts the leg into a conference. What we keep is the part
 * Telnyx does not -- which keyed digits mean which conference, and who a room
 * is holding.
 *
 * Two things about conferences are worth knowing before reading the state
 * machine. They expire after four hours whether or not anyone is still on
 * them, so a long-lived room's conference id goes stale underneath us and has
 * to be remade on the next join. And the id is only knowable after the first
 * caller creates it, so the first caller and the tenth take different paths
 * through the same function.
 *
 * The code is asked for on the keypad, never by voice: one misheard digit is a
 * different room that also exists, and the caller lands in a stranger's
 * conversation with nothing to tell them they went wrong. An agent keys it
 * too, with DTMF, so a person and an agent arrive the same way.
 */
import { createPublicKey, verify as verifySignature, timingSafeEqual } from "node:crypto";

/** Where Telnyx's REST API lives. */
export const TELNYX_API = "https://api.telnyx.com/v2";

/**
 * Telnyx's own voice, so a room prompt costs nothing beyond the call. A
 * Polly or ElevenLabs voice reads better and bills separately; the name is
 * configuration rather than a constant for exactly that reason.
 */
export const DEFAULT_VOICE = "Telnyx.KokoroTTS.af";

/**
 * The voice a leg falls back to when the good one fails.
 *
 * Telnyx's Kokoro voice answered a prompt with a 500 once (2026-09-09), and
 * what the caller got was a gather with no speech in it, ended at once with
 * no digits, and asked again -- a line that "just repeats itself", silently.
 * The plain Telnyx voice is older and worse and has not been seen to fail,
 * which is the quality that matters on the second try.
 */
export const FALLBACK_VOICE = "female";

/**
 * How long a caller has between digits before the code is treated as done.
 * Telnyx's default of five seconds did not fire in practice; set explicitly
 * so a partial code comes back quickly and we can say how many digits we got.
 */
const INTER_DIGIT_MS = 4000;

/** How many times a caller is asked for a code before being let go. */
const MAX_ASKS = 3;

/** How long a signed webhook stays acceptable. Telnyx's own SDKs use five minutes. */
const SIGNATURE_TOLERANCE_MS = 5 * 60 * 1000;

/** A conference Telnyx will discard on its own, so we stop trusting ours first. */
const CONFERENCE_TTL_MS = 4 * 60 * 60 * 1000;

const NUMBER_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve"];

/** "six digit", said rather than written. */
export function digitWords(length: number): string {
  return `${NUMBER_WORDS[length] ?? String(length)} digit`;
}

export interface RoomInfo {
  /** The room code, which is the room's whole identity on the phone. */
  code: string;
  /** Telnyx's id for the conference, once a first caller has made one. */
  conferenceId: string | null;
  /** How many legs we have put in, less the ones we have seen leave. */
  callers: number;
  startedAt: number;
}

/** Somebody on the line in a room, person or agent. */
export interface Participant {
  /** The call-control id of their leg. */
  leg: string;
  /** The number they called from, when the network told us. */
  from: string;
  /** A name, when one is known: an agent says who it is before it dials. */
  name: string;
  joinedAt: number;
}

interface Room extends RoomInfo {
  /** Legs currently in the room, so a caller is never counted twice. */
  legs: Map<string, Participant>;
}

/** Sending a text. Injected because the number that sends is not always the one called. */
export interface Sms {
  send(to: string, text: string): Promise<boolean>;
}

export interface TelnyxEvent {
  event_type?: string;
  payload?: Record<string, unknown>;
}

/**
 * One caller, as an `onCode` hook sees them: enough to put them in a room,
 * tell them something, ask them something else, or let them go.
 */
export interface CallHandle {
  readonly leg: string;
  /** The number they called from, or "" when withheld. */
  readonly from: string;
  /** Put them in the room on `code`. `welcome` is said once they are in. */
  join(code: string, welcome?: string): Promise<void>;
  /** Say something to them alone. */
  speak(text: string): Promise<boolean>;
  /** Ask a keypad question; `answer` gets the digits (or "" for none). */
  gather(prompt: string, options: GatherOptions, answer: (digits: string) => Promise<void>): Promise<void>;
  hangup(): Promise<boolean>;
  /** Say `text`, then hang up. */
  goodbye(text: string): Promise<void>;
}

export interface GatherOptions {
  validDigits?: string;
  minimumDigits?: number;
  maximumDigits?: number;
  timeoutMillis?: number;
  terminatingDigit?: string;
}

/**
 * What a code turned out to be.
 *
 * - `true` (or nothing): an ordinary room, joined with the default welcome.
 * - `{ welcome }`: an ordinary room, with this said on the way in.
 * - `{ reject }`: not a room; this is said, and the caller may try again.
 * - `"handled"`: the hook already did something with the call itself.
 */
export type CodeAnswer = void | true | "handled" | { welcome: string } | { reject: string };

export interface GroupCallOptions {
  /** A Telnyx API key with call-control rights. */
  apiKey: string;
  /**
   * The account's ed25519 public key, base64, from the portal. Without it
   * every webhook is refused: an unauthenticated call-control webhook lets a
   * stranger drive calls we are paying for.
   */
  publicKey: string;
  /** How many digits a room code has. nixamp uses six; a private room can live with four. */
  codeLength?: number;
  /** What the caller hears first. Defaults to asking for the code. */
  greeting?: string;
  voice?: string;
  /**
   * Voice settings sent with every prompt in the main voice, for voices that
   * need them -- an ElevenLabs voice needs `{ api_key_ref }` naming the key
   * Telnyx holds.
   */
  voiceSettings?: Record<string, unknown>;
  /** A ceiling per room, so one room cannot spend the whole balance. */
  maxParticipants?: number;
  /** Prefix of the conference names we create on Telnyx. */
  conferencePrefix?: string;
  /**
   * What a keyed code means. Without it, any code opens a room -- the code
   * is a rendezvous, not a credential. With it, an app can keep a list of
   * rooms that exist, route some codes elsewhere, or refuse.
   */
  onCode?: (code: string, call: CallHandle) => Promise<CodeAnswer> | CodeAnswer;
  /** A person or agent got into a room. */
  onJoin?: (code: string, who: Participant, room: RoomInfo) => void;
  /** A person or agent left a room. */
  onLeave?: (code: string, who: Participant, room: RoomInfo) => void;
  /** Injected for tests. */
  now?: () => number;
  fetch?: typeof globalThis.fetch;
  onEvent?: (message: string) => void;
}

/**
 * A room code, from whatever the caller keyed.
 *
 * Digits only, and exactly `length` of them. One short is not a near miss to
 * be charitable about -- it is a different room, and guessing which one they
 * meant would drop somebody into a stranger's conversation.
 */
export function roomCodeFrom(entered: unknown, length = 6): string {
  if (typeof entered !== "string" && typeof entered !== "number") return "";
  const digits = String(entered).replace(/\D/g, "");
  return digits.length === length ? digits : "";
}

/** How a code is read back: one digit at a time, because 4829 is not a number. */
export function spokenCode(code: string): string {
  return code.split("").join(", ");
}

/**
 * How many people are in a room, said to the one who just walked in.
 *
 * The count includes them: "there are 3 people in here" is what you say to the
 * third person, and "you are the first one here" is what you say to the first,
 * who would otherwise be told there is one person in an empty room.
 */
export function peopleHere(callers: number): string {
  if (callers <= 1) return "You are the first one here. Say hello when somebody joins.";
  if (callers === 2) return "There is one other person in here. Say hello.";
  return `There are ${callers} people in here. Say hello.`;
}

/**
 * Telnyx signs `${timestamp}|${body}` with ed25519 and sends both back in
 * headers. Node will not take a bare 32-byte key, so it is wrapped in the
 * fixed SPKI prefix that says "this is ed25519" and handed over as DER.
 */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function ed25519KeyFrom(base64Key: string): ReturnType<typeof createPublicKey> | null {
  let raw: Buffer;
  try {
    raw = Buffer.from(base64Key, "base64");
  } catch {
    return null;
  }
  if (raw.length !== 32) return null;
  try {
    return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
  } catch {
    return null;
  }
}

/**
 * Whether a webhook really came from Telnyx.
 *
 * The body has to be the bytes that arrived. Parsing and reserialising JSON
 * changes key order and whitespace, and the signature is over the original.
 */
export function verifyTelnyx(
  publicKey: string,
  rawBody: string,
  signature: string | undefined,
  timestamp: string | undefined,
  now: number = Date.now(),
): boolean {
  return verifyWith(publicKey ? ed25519KeyFrom(publicKey) : null, rawBody, signature, timestamp, now);
}

function verifyWith(
  key: ReturnType<typeof createPublicKey> | null,
  rawBody: string,
  signature: string | undefined,
  timestamp: string | undefined,
  now: number,
): boolean {
  if (key === null || !signature || !timestamp) return false;
  const sent = Number(timestamp) * 1000;
  if (!Number.isFinite(sent)) return false;
  // Both directions: a replayed webhook is old, and a clock-skewed forgery
  // from the future is no more trustworthy for being ahead.
  if (Math.abs(now - sent) > SIGNATURE_TOLERANCE_MS) return false;
  let sig: Buffer;
  try {
    sig = Buffer.from(signature, "base64");
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  try {
    return verifySignature(null, Buffer.from(`${timestamp}|${rawBody}`, "utf8"), key, sig);
  } catch {
    return false;
  }
}

/**
 * The group call, as a thing that answers webhooks.
 *
 * It owns no socket and no timer. The server hands it a verified event and it
 * issues whatever call-control commands that event calls for, which makes the
 * whole state machine testable with a fetch that records what it was asked.
 */
export class GroupCall {
  protected readonly rooms = new Map<string, Room>();
  /** Which room a leg is heading for, between asking and being answered. */
  private readonly legRoom = new Map<string, string>();
  /** The number each caller is calling from. */
  protected readonly legFrom = new Map<string, string>();
  /** Legs answering a question an `onCode` hook asked, and what to do with the answer. */
  private readonly pendingGather = new Map<string, (digits: string) => Promise<void>>();
  /** How many times each leg has been asked for a code, so it is not forever. */
  private readonly asks = new Map<string, number>();
  /** Legs whose voice failed once, which hear the plain one from then on. */
  private readonly plainVoice = new Set<string>();
  /** Names promised for callers about to arrive from a number: agents announce themselves. */
  private readonly expected: { code: string; from: string; name: string; until: number }[] = [];
  private readonly key: ReturnType<typeof createPublicKey> | null;
  protected readonly fetch: typeof globalThis.fetch;
  protected readonly now: () => number;

  protected readonly options: GroupCallOptions;

  constructor(options: GroupCallOptions) {
    this.options = options;
    this.key = options.publicKey ? ed25519KeyFrom(options.publicKey) : null;
    this.fetch = options.fetch ?? globalThis.fetch;
    this.now = options.now ?? Date.now;
  }

  /** True when this instance can actually check a signature. */
  get armed(): boolean {
    return this.key !== null && this.options.apiKey.length > 0;
  }

  get codeLength(): number {
    return this.options.codeLength ?? 6;
  }

  /** Whether a webhook really came from Telnyx. See `verifyTelnyx`. */
  verify(rawBody: string, signature: string | undefined, timestamp: string | undefined): boolean {
    return verifyWith(this.key, rawBody, signature, timestamp, this.now());
  }

  /** The rooms with someone in them, busiest first. */
  list(): { code: string; callers: number; startedAt: number }[] {
    return [...this.rooms.values()]
      .filter((room) => room.callers > 0)
      .map(({ code, callers, startedAt }) => ({ code, callers, startedAt }))
      .sort((a, b) => b.callers - a.callers || a.startedAt - b.startedAt);
  }

  /** Who is on the line in a room, earliest first. */
  participants(code: string): Participant[] {
    const room = this.rooms.get(code);
    return room ? [...room.legs.values()].sort((a, b) => a.joinedAt - b.joinedAt) : [];
  }

  /**
   * Name the next caller from `from` into `code`, for the next two minutes.
   *
   * An agent's call arrives from a shared caller id and keys a code like
   * anybody else; this is how the room learns it is "riotcoder" rather than a
   * number. Matched on number and room, so it cannot rename a stranger in a
   * different room.
   */
  expect(code: string, from: string, name: string, withinMs = 2 * 60 * 1000): void {
    this.expected.push({ code, from: normalNumber(from), name: name.slice(0, 60), until: this.now() + withinMs });
  }

  /**
   * Drive one call-control event.
   *
   * Every branch returns rather than falling through, because an event we do
   * not handle is the normal case -- Telnyx sends a dozen kinds per call and
   * this cares about five.
   */
  async handle(event: TelnyxEvent): Promise<void> {
    const type = event.event_type ?? "";
    const payload = event.payload ?? {};
    const leg = typeof payload["call_control_id"] === "string" ? payload["call_control_id"] : "";
    if (!leg) return;

    if (type === "call.initiated") {
      // Only inbound. An outbound leg we dialled is not somebody calling in,
      // and answering it would be answering ourselves.
      if (payload["direction"] !== "incoming") return;
      if (typeof payload["from"] === "string") this.legFrom.set(leg, payload["from"]);
      await this.command(leg, "answer", {});
      return;
    }

    if (type === "call.answered") {
      // An answered outbound leg is somebody else's business.
      if (payload["direction"] === "outgoing") return;
      await this.ask(leg);
      return;
    }

    if (type === "call.speak.failed") {
      // The voice, not the caller, failed. Everything this leg hears from now
      // on is in the plain voice; the gather this speech belonged to ends on
      // its own and is asked again, audibly this time.
      this.plainVoice.add(leg);
      this.options.onEvent?.("  a prompt could not be spoken; using the plain voice.");
      return;
    }

    if (type === "call.gather.ended") {
      const digits = typeof payload["digits"] === "string" ? payload["digits"] : "";

      // A gather that ended because the caller hung up is not an answer, and
      // anything sent to that leg now is a 422 for the log.
      if (payload["status"] === "call_hangup") return;

      // A leg answering something a hook asked is answering that, not keying a
      // room code -- the same event carries both, so the question we asked is
      // what decides how to read it.
      const pending = this.pendingGather.get(leg);
      if (pending !== undefined) {
        this.pendingGather.delete(leg);
        await pending(digits);
        return;
      }

      const code = roomCodeFrom(digits, this.codeLength);
      if (!code) {
        // Re-ask rather than guess, and say what we got: five digits and
        // silence is a caller who thinks the line is broken.
        const got = digits.replace(/\D/g, "").length;
        await this.ask(leg, got > 0 ? `I only got ${got} digits. ` : "I did not get a code. ");
        return;
      }
      await this.routeCode(leg, code);
      return;
    }

    if (type === "conference.participant.left" || type === "call.hangup") {
      this.release(leg);
      this.legFrom.delete(leg);
      this.pendingGather.delete(leg);
      this.asks.delete(leg);
      this.plainVoice.delete(leg);
      return;
    }
  }

  /** Hand a well-formed code to the app, and act on what it says the code is. */
  private async routeCode(leg: string, code: string): Promise<void> {
    const answer = this.options.onCode ? await this.options.onCode(code, this.callHandle(leg)) : undefined;
    if (answer === "handled") {
      this.asks.delete(leg);
      return;
    }
    if (answer && typeof answer === "object" && "reject" in answer) {
      // Not a room. Asked again, because a typo deserves a second go -- and
      // the ask count still runs, so nobody can sit guessing codes forever.
      await this.ask(leg, `${answer.reject} `);
      return;
    }
    this.asks.delete(leg);
    const welcome = answer && typeof answer === "object" && "welcome" in answer ? answer.welcome : undefined;
    await this.join(leg, code, welcome);
  }

  /** A caller, as a hook sees them. */
  protected callHandle(leg: string): CallHandle {
    return {
      leg,
      from: this.legFrom.get(leg) ?? "",
      join: (code, welcome) => this.join(leg, code, welcome),
      speak: (text) => this.command(leg, "speak", { payload: text, ...this.voiceBody(leg) }),
      gather: (prompt, options, answer) => this.gather(leg, prompt, options, answer),
      hangup: () => this.command(leg, "hangup", {}),
      goodbye: async (text) => {
        await this.command(leg, "speak", { payload: text, ...this.voiceBody(leg) });
        await this.command(leg, "hangup", {});
      },
    };
  }

  /** Ask a keypad question whose answer goes to `answer`, not to the room-code path. */
  private async gather(leg: string, prompt: string, options: GatherOptions, answer: (digits: string) => Promise<void>): Promise<void> {
    // Set before the prompt, not after: the answer can arrive while we are
    // still awaiting the command that asked for it.
    this.pendingGather.set(leg, answer);
    await this.command(leg, "gather_using_speak", {
      payload: prompt,
      ...this.voiceBody(leg),
      valid_digits: options.validDigits ?? "0123456789",
      minimum_digits: options.minimumDigits ?? 1,
      maximum_digits: options.maximumDigits ?? 1,
      ...(options.terminatingDigit ? { terminating_digit: options.terminatingDigit } : {}),
      timeout_millis: options.timeoutMillis ?? 12000,
    });
  }

  /**
   * Ask for a room code, on the keypad.
   *
   * Short, because callers key the code over the prompt and a long one costs
   * digits. A full-length code ends the gather on its own, so the caller does
   * not have to press anything after; # is there for the ones who do it anyway.
   */
  private async ask(leg: string, prefix = ""): Promise<void> {
    const asked = (this.asks.get(leg) ?? 0) + 1;
    this.asks.set(leg, asked);
    if (asked > MAX_ASKS) {
      // Three gathers with no room in them is not a caller who needs a fourth
      // prompt. Whatever is wrong -- their keypad, our voice -- repeating
      // ourselves is the failure that was reported, so this ends instead.
      await this.command(leg, "speak", { payload: "I did not get a room code. Goodbye.", ...this.voiceBody(leg) });
      await this.command(leg, "hangup", {});
      return;
    }

    const length = this.codeLength;
    const askCode = `Enter the ${digitWords(length)} room code.`;
    const greeting = this.options.greeting ?? `Welcome. ${askCode}`;
    const payload = asked === 1 ? `${prefix}${greeting}` : `${prefix}${askCode}`;

    await this.command(leg, "gather_using_speak", {
      payload,
      ...this.voiceBody(leg),
      valid_digits: "0123456789",
      minimum_digits: length,
      maximum_digits: length,
      terminating_digit: "#",
      timeout_millis: 20000,
      inter_digit_timeout_millis: INTER_DIGIT_MS,
    });
  }

  /**
   * Put a leg into a room, making the conference if it is the first one there.
   *
   * `welcome` is what the caller hears once they are in, before the count of
   * who else is.
   */
  async join(leg: string, code: string, welcome = `Welcome to room ${spokenCode(code)}. `): Promise<void> {
    const room = this.room(code);

    if (room.callers >= this.maxParticipants) {
      await this.command(leg, "speak", { payload: "That room is full. Goodbye.", ...this.voiceBody(leg) });
      await this.command(leg, "hangup", {});
      return;
    }

    this.legRoom.set(leg, code);

    // A conference we made more than four hours ago is gone on Telnyx's side
    // whatever our map says, so it is remade rather than joined.
    const stale = this.now() - room.startedAt > CONFERENCE_TTL_MS;
    if (room.conferenceId !== null && !stale) {
      const joined = await this.request(
        `/conferences/${encodeURIComponent(room.conferenceId)}/actions/join`,
        { call_control_id: leg, start_conference_on_enter: true },
      );
      if (joined !== null) {
        this.enter(room, leg);
        await this.greet(room, leg, welcome);
        return;
      }
      // The id was stale in a way the clock did not predict -- an operator
      // ended it, or Telnyx did. Fall through and make a new one.
      room.conferenceId = null;
    }

    const created = await this.request("/conferences", {
      name: `${this.options.conferencePrefix ?? "groupcall"}-${this.now()}-${room.legs.size}`,
      call_control_id: leg,
      start_conference_on_create: true,
      max_participants: this.maxParticipants,
    });

    const id = created && typeof created === "object"
      ? ((created as Record<string, unknown>)["data"] as Record<string, unknown> | undefined)?.["id"]
      : undefined;

    if (typeof id !== "string") {
      await this.command(leg, "speak", { payload: "Sorry, that room could not be opened. Goodbye.", ...this.voiceBody(leg) });
      await this.command(leg, "hangup", {});
      this.legRoom.delete(leg);
      return;
    }

    room.conferenceId = id;
    room.startedAt = this.now();
    this.enter(room, leg);
    await this.greet(room, leg, welcome);
  }

  private enter(room: Room, leg: string): void {
    if (room.legs.has(leg)) return;
    const from = this.legFrom.get(leg) ?? "";
    const who: Participant = { leg, from, name: this.claimName(room.code, from), joinedAt: this.now() };
    room.legs.set(leg, who);
    room.callers = room.legs.size;
    this.options.onEvent?.(`  ${who.name || "a caller"} joined a room (${room.callers} on the line).`);
    this.options.onJoin?.(room.code, who, this.info(room));
  }

  /** The name an agent registered for this number and room, used once. */
  private claimName(code: string, from: string): string {
    const now = this.now();
    for (let i = this.expected.length - 1; i >= 0; i--) if (this.expected[i]!.until < now) this.expected.splice(i, 1);
    const number = normalNumber(from);
    if (!number) return "";
    const at = this.expected.findIndex((one) => one.code === code && one.from === number);
    if (at < 0) return "";
    const [found] = this.expected.splice(at, 1);
    return found!.name;
  }

  /**
   * Say hello to somebody who just joined, and only to them.
   *
   * Spoken into the conference rather than at the leg, because the leg is in
   * the conference now and a speak on it is what the join interrupts. Telnyx
   * addresses conference speech to particular participants, so the others in
   * the room do not hear every arrival welcomed.
   */
  private async greet(room: Room, leg: string, welcome: string): Promise<void> {
    if (room.conferenceId === null) return;
    await this.request(`/conferences/${encodeURIComponent(room.conferenceId)}/actions/speak`, {
      payload: `${welcome}${peopleHere(room.callers)}`,
      ...this.voiceBody(leg),
      call_control_ids: [leg],
    });
  }

  /**
   * A line said into a room, to everybody on the phone in it. False when
   * nobody is on the phone there, which is most of the time and costs nothing.
   */
  async say(code: string, text: string, voice?: string, settings?: Record<string, unknown>): Promise<boolean> {
    const room = this.rooms.get(code);
    if (!room || room.conferenceId === null || room.callers === 0) return false;
    const said = text.replace(/\s+/g, " ").trim().slice(0, 500);
    if (said === "") return false;
    const voiceSettings = settings ?? (!voice ? this.options.voiceSettings : undefined);
    const answer = await this.request(`/conferences/${encodeURIComponent(room.conferenceId)}/actions/speak`, {
      payload: said,
      voice: voice || this.voice,
      // An ElevenLabs voice needs the key Telnyx holds for it, by name.
      ...(voiceSettings ? { voice_settings: voiceSettings } : {}),
    });
    return answer !== null;
  }

  /** Hang up one participant in a room. */
  async kick(code: string, leg: string): Promise<boolean> {
    if (!this.rooms.get(code)?.legs.has(leg)) return false;
    return this.command(leg, "hangup", {});
  }

  /** Whether anybody is on the phone in a room. */
  hasCallers(code: string): boolean {
    const room = this.rooms.get(code);
    return room !== undefined && room.conferenceId !== null && room.callers > 0;
  }

  /** How many people are on the phone in a room. */
  callersIn(code: string): number {
    return this.rooms.get(code)?.callers ?? 0;
  }

  /** A leg that hung up or was dropped, wherever it was. */
  private release(leg: string): void {
    const code = this.legRoom.get(leg);
    this.legRoom.delete(leg);
    if (code === undefined) return;
    const room = this.rooms.get(code);
    if (room === undefined) return;
    const who = room.legs.get(leg);
    room.legs.delete(leg);
    room.callers = room.legs.size;
    if (who) this.options.onLeave?.(code, who, this.info(room));
    if (room.callers === 0) {
      // Telnyx ends an empty conference itself; keeping the code would only
      // mean handing the next caller a dead id.
      this.rooms.delete(code);
      this.options.onEvent?.("  a room is empty.");
    }
  }

  private info(room: Room): RoomInfo {
    return { code: room.code, conferenceId: room.conferenceId, callers: room.callers, startedAt: room.startedAt };
  }

  /** The room on this code, made if nobody is using it. */
  private room(code: string): Room {
    const existing = this.rooms.get(code);
    if (existing !== undefined) return existing;
    const room: Room = { code, conferenceId: null, callers: 0, startedAt: this.now(), legs: new Map() };
    this.rooms.set(code, room);
    return room;
  }

  protected get voice(): string {
    return this.options.voice ?? DEFAULT_VOICE;
  }

  /** The voice for this leg: the good one, unless it has already failed them. */
  protected voiceFor(leg: string): string {
    return this.plainVoice.has(leg) ? FALLBACK_VOICE : this.voice;
  }

  /** `voice`, plus its settings while the good voice is the one in use. */
  protected voiceBody(leg: string): Record<string, unknown> {
    const voice = this.voiceFor(leg);
    return voice === this.voice && this.options.voiceSettings ? { voice, voice_settings: this.options.voiceSettings } : { voice };
  }

  private get maxParticipants(): number {
    return this.options.maxParticipants ?? 50;
  }

  /** One call-control command. True when Telnyx accepted it. */
  protected async command(leg: string, action: string, body: unknown): Promise<boolean> {
    const path = `/calls/${encodeURIComponent(leg)}/actions/${action}`;
    return (await this.request(path, body)) !== null;
  }

  /** A POST to Telnyx, or null if it did not work. */
  protected async request(path: string, body: unknown): Promise<unknown | null> {
    try {
      const response = await this.fetch(`${TELNYX_API}${path}`, {
        method: "POST",
        headers: { authorization: `Bearer ${this.options.apiKey}`, "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!response.ok) {
        // A command against a leg that already hung up is a 422 and is not
        // worth a stack trace; it is the ordinary end of a race.
        this.options.onEvent?.(`  telnyx ${path} -> ${response.status}`);
        return null;
      }
      const text = await response.text();
      return text ? (JSON.parse(text) as unknown) : {};
    } catch (error) {
      this.options.onEvent?.(`  telnyx ${path} failed: ${(error as Error).message}`);
      return null;
    }
  }
}

/** +1XXXXXXXXXX from whatever shape a North American number arrived in. */
export function normalNumber(input: string): string {
  const digits = String(input || "").replace(/[^\d]/g, "");
  if (digits.length === 10) return `+1${digits}`;
  return digits ? `+${digits}` : "";
}

/** Texting, over Telnyx, from a number that has a messaging profile. */
export function telnyxSms(
  { apiKey, from, fetch = globalThis.fetch, onEvent }: {
    apiKey: string;
    from: string;
    fetch?: typeof globalThis.fetch;
    onEvent?: (message: string) => void;
  },
): Sms {
  return {
    async send(to: string, text: string): Promise<boolean> {
      try {
        const response = await fetch(`${TELNYX_API}/messages`, {
          method: "POST",
          headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
          body: JSON.stringify({ from, to, text }),
        });
        if (!response.ok) {
          onEvent?.(`  sms to ${to} -> ${response.status}`);
          return false;
        }
        return true;
      } catch (error) {
        onEvent?.(`  sms to ${to} failed: ${(error as Error).message}`);
        return false;
      }
    },
  };
}

/** Constant-time compare, for the places a token is checked rather than signed. */
export function sameSecret(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * A fresh random room code of `length` digits that `taken` says is free.
 * Codes easy to stumble on -- all one digit, a leading zero some people
 * drop, a straight run like 1234 -- are kept for nobody.
 */
export function newRoomCode(length = 4, taken: (code: string) => boolean = () => false, random: () => number = cryptoRandom): string {
  for (let i = 0; i < 1000; i++) {
    let code = "";
    for (let d = 0; d < length; d++) code += String(Math.floor(random() * 10));
    if (/^(\d)\1+$/.test(code) || code.startsWith("0") || "0123456789".includes(code) || "9876543210".includes(code)) continue;
    if (!taken(code)) return code;
  }
  throw new Error(`no free ${length}-digit room code`);
}

function cryptoRandom(): number {
  const buf = new Uint32Array(1);
  globalThis.crypto.getRandomValues(buf);
  return buf[0]! / 2 ** 32;
}
