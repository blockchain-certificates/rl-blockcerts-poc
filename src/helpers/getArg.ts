export default function getArg (customArg: string): string {
  const args = process.argv;
  return args.find(arg => arg.includes(customArg))?.split('=')[1];
}
