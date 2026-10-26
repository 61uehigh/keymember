/**
 * ### SshWireError
 *
 * Input did not follow the SSH wire format (RFC 4251 §5).
 */
export class SshWireError extends Error {
  override readonly name = "SshWireError";
}

/**
 * ### SshReader
 *
 * Reads RFC 4251 data types from a buffer, refusing to read past its end.
 */
export class SshReader {
  readonly #bytes: Uint8Array;
  #offset = 0;

  /**
   * ### constructor
   *
   * @param bytes Data to read
   */
  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  /**
   * ### done
   *
   * Whether everything was read.
   */
  get done(): boolean {
    return this.#offset >= this.#bytes.length;
  }

  /**
   * ### byte
   *
   * Reads one byte.
   *
   * @returns The byte
   */
  byte(): number {
    const value = this.#bytes[this.#offset];

    if (value === undefined) {
      throw new SshWireError("Unexpected end of data");
    }

    this.#offset += 1;

    return value;
  }

  /**
   * ### uint32
   *
   * Reads a big-endian 32-bit unsigned integer.
   *
   * @returns The integer
   */
  uint32(): number {
    const bytes = this.raw(4);

    return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0);
  }

  /**
   * ### raw
   *
   * Reads a fixed number of bytes.
   *
   * @param length Byte count
   * @returns The bytes
   */
  raw(length: number): Uint8Array {
    if (length < 0 || this.#offset + length > this.#bytes.length) {
      throw new SshWireError("Unexpected end of data");
    }

    const bytes = this.#bytes.subarray(this.#offset, this.#offset + length);

    this.#offset += length;

    return bytes;
  }

  /**
   * ### string
   *
   * Reads a length-prefixed byte string.
   *
   * @returns The bytes
   */
  string(): Uint8Array {
    return this.raw(this.uint32());
  }

  /**
   * ### text
   *
   * Reads a length-prefixed UTF-8 string.
   *
   * @returns The text
   */
  text(): string {
    return new TextDecoder("utf-8", { fatal: true }).decode(this.string());
  }

  /**
   * ### mpint
   *
   * Reads a non-negative multiple-precision integer, returned without the sign byte.
   *
   * @returns Big-endian magnitude
   */
  mpint(): Uint8Array {
    const bytes = this.string();

    if ((bytes[0] ?? 0) & 0x80) {
      throw new SshWireError("Negative integers are not used in keys");
    }

    return bytes[0] === 0 ? bytes.subarray(1) : bytes;
  }
}

/**
 * ### SshWriter
 *
 * Builds RFC 4251 data.
 */
export class SshWriter {
  readonly #parts: Array<Uint8Array> = [];

  /**
   * ### byte
   *
   * Appends one byte.
   *
   * @param value Byte
   * @returns This writer
   */
  byte(value: number): this {
    this.#parts.push(Uint8Array.of(value));

    return this;
  }

  /**
   * ### uint32
   *
   * Appends a big-endian 32-bit unsigned integer.
   *
   * @param value Integer
   * @returns This writer
   */
  uint32(value: number): this {
    const bytes = new Uint8Array(4);

    new DataView(bytes.buffer).setUint32(0, value);
    this.#parts.push(bytes);

    return this;
  }

  /**
   * ### raw
   *
   * Appends bytes as they are.
   *
   * @param bytes Bytes
   * @returns This writer
   */
  raw(bytes: Uint8Array): this {
    this.#parts.push(bytes);

    return this;
  }

  /**
   * ### string
   *
   * Appends a length-prefixed byte or UTF-8 string.
   *
   * @param value Bytes or text
   * @returns This writer
   */
  string(value: Uint8Array | string): this {
    const bytes =
      typeof value === "string" ? new TextEncoder().encode(value) : value;

    return this.uint32(bytes.length).raw(bytes);
  }

  /**
   * ### mpint
   *
   * Appends a non-negative multiple-precision integer from its big-endian magnitude.
   *
   * @param magnitude Big-endian bytes
   * @returns This writer
   */
  mpint(magnitude: Uint8Array): this {
    let start = 0;

    while (start < magnitude.length && magnitude[start] === 0) {
      start += 1;
    }

    const trimmed = magnitude.subarray(start);

    // A leading 1 bit would read as negative, so such values get a zero byte in front
    return this.string(
      (trimmed[0] ?? 0) & 0x80
        ? Uint8Array.from([0, ...trimmed])
        : Uint8Array.from(trimmed),
    );
  }

  /**
   * ### bytes
   *
   * The data written so far.
   *
   * @returns Concatenated bytes
   */
  bytes(): Uint8Array {
    const total = this.#parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;

    for (const part of this.#parts) {
      out.set(part, offset);
      offset += part.length;
    }

    return out;
  }
}
