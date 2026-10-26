// Rules for a NEW master password. Existing vaults are never checked against these.
export const MIN_LENGTH = 9;

const COMMON = [
  'password', 'passw0rd', 'letmein', 'welcome', 'iloveyou', 'qwerty', 'qwertyuiop', 'asdfgh', 'zxcvbn',
  'admin', 'abc123', 'monkey', 'dragon', 'football', 'baseball', 'master', 'login', 'princess',
  'sunshine', 'shadow', 'superman', 'trustno1', 'changeme', '123456', '1234567', '12345678', '123456789',
  'otpal', 'authenticator', 'google', 'microsoft',
];

const norm = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, '');

/** Returns a message explaining what is wrong, or null if the password is acceptable. */
export function checkPassword(pw) {
  if ([...pw].length < MIN_LENGTH) return `Use at least ${MIN_LENGTH} characters. A few random words in a row work well.`;
  if (new Set(pw).size < 6) return 'That password repeats too few different characters.';
  const flat = norm(pw);
  // Passwords that are only a common word plus digits or filler are the first thing guessed.
  const stripped = flat.replace(/[0-9]/g, '');
  for (const word of COMMON) {
    if (flat === word || stripped === word || (flat.length <= word.length + 6 && flat.includes(word))) return 'That password is too common.';
  }
  if (/^(.)\1+$/.test(pw) || /^(?:0123456789|1234567890|abcdefghij|qwertyuiop)/i.test(pw.replace(/\s/g, ''))) {
    return 'That password is too easy to guess.';
  }
  return null;
}
