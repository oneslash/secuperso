export function createLocalID(prefix: string): string {
  const random = Math.random().toString(16).slice(2, 10)
  return `${prefix}-${Date.now().toString(16)}-${random}`
}
