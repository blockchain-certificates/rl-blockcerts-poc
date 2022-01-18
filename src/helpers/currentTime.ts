export default function currentTime (): string {
  return new Date(Date.now()).toISOString();
}
