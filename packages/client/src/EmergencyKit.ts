import { formatSecretKey } from "@keymember/core";
import type { SecretKey } from "@keymember/core";
import { PDFDocument, rgb, StandardFonts } from "pdf-lib";
import QRCode from "qrcode";

/**
 * ### EmergencyKitInput
 *
 * What goes on the kit. The password is deliberately absent: the user writes it by hand.
 */
export interface EmergencyKitInput {
  /**
   * ### serverUrl
   *
   * Server origin.
   */
  readonly serverUrl: string;

  /**
   * ### email
   *
   * Account email.
   */
  readonly email: string;

  /**
   * ### secretKey
   *
   * Account Secret Key.
   */
  readonly secretKey: SecretKey;

  /**
   * ### createdAt
   *
   * Date printed on the kit.
   */
  readonly createdAt: Date;
}

/**
 * ### addDeviceUri
 *
 * URI encoded in the kit's QR code, carrying everything except the password.
 *
 * @param input Kit contents
 * @returns The `keymember://add-device` URI
 */
export function addDeviceUri(input: EmergencyKitInput): string {
  const params = new URLSearchParams({
    server: input.serverUrl,
    email: input.email,
    key: formatSecretKey(input.secretKey),
  });

  return `keymember://add-device?${params.toString()}`;
}

/**
 * ### renderEmergencyKit
 *
 * Renders the printable Emergency Kit PDF. Text is English only because the standard PDF
 * fonts cannot render Hangul without embedding a font file.
 *
 * @param input Kit contents
 * @returns The PDF bytes
 */
export async function renderEmergencyKit(
  input: EmergencyKitInput,
): Promise<Uint8Array> {
  const pdf = await PDFDocument.create();
  const page = pdf.addPage([595.28, 841.89]);
  const regular = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const mono = await pdf.embedFont(StandardFonts.CourierBold);
  const ink = rgb(0.1, 0.1, 0.1);
  let y = 780;

  const text = (value: string, size: number, font = regular, x = 56): void => {
    page.drawText(value, { x, y, size, font, color: ink });
    y -= size + 10;
  };

  pdf.setTitle("keymember Emergency Kit");
  text("keymember Emergency Kit", 24, bold);
  text(
    `Created ${input.createdAt.toISOString().slice(0, 10)} for ${input.email}`,
    11,
  );
  y -= 10;
  text(
    "Keep this page somewhere safe and offline, such as a locked drawer.",
    11,
  );
  text(
    "You need it to sign in on a new device. Nobody, including your admins,",
    11,
  );
  text(
    "can read your data without both this Secret Key and your password.",
    11,
  );
  y -= 16;

  text("SERVER", 9, bold);
  text(input.serverUrl, 13);
  text("EMAIL", 9, bold);
  text(input.email, 13);
  text("SECRET KEY", 9, bold);
  text(formatSecretKey(input.secretKey), 16, mono);
  text("PASSWORD (write it by hand)", 9, bold);
  page.drawRectangle({
    x: 56,
    y: y - 14,
    width: 300,
    height: 28,
    borderColor: ink,
    borderWidth: 1,
  });
  y -= 60;

  const qr = QRCode.create(addDeviceUri(input), { errorCorrectionLevel: "M" });
  const cell = 4;
  const size = qr.modules.size;
  const originY = y - size * cell;

  for (let row = 0; row < size; row += 1) {
    for (let col = 0; col < size; col += 1) {
      if (qr.modules.get(row, col) === 1) {
        page.drawRectangle({
          x: 56 + col * cell,
          y: originY + (size - 1 - row) * cell,
          width: cell,
          height: cell,
          color: ink,
        });
      }
    }
  }

  y = originY - 24;
  text(
    "Scan to add a device. The QR code holds the server, email and Secret Key,",
    10,
  );
  text("but never the password.", 10);

  return pdf.save();
}
