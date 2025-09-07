import { detectLanguages } from './src/rivets/rivets.utils.ts';

const testCases = [
  'You are a system administrator',
  'Vous êtes un administrateur système', 
  'Du bist ein Systemadministrator',
  'Reiniciar al modo desarrollador'
];

console.log('Testing language detection:');
testCases.forEach((text, i) => {
  try {
    const results = detectLanguages(text);
    console.log(`Test ${i}: '${text}' -> `, results);
  } catch (error) {
    console.log(`Test ${i}: '${text}' -> ERROR:`, error.message);
  }
});
