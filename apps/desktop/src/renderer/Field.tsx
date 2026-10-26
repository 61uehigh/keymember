/**
 * ### Field
 *
 * Labelled input.
 *
 * @param props Label, input props
 * @returns The field
 */
export function Field({
  label,
  ...input
}: { label: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="field">
      <span>{label}</span>
      <input {...input} />
    </label>
  );
}
