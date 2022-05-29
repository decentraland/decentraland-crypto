/** Takes the current date, add or subtract minutes, and returns it */
export function moveMinutes(minutes: number): Date {
  const date = new Date()
  date.setMinutes(date.getMinutes() + minutes)
  return date
}
