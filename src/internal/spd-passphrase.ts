/**
 * Diceware-style passphrase generation for SPD.generatePassphrase().
 *
 * WORDLIST has 240 distinct 4-letter words (~7.9 bits/word). Indices are drawn
 * by rejection sampling from 16-bit CSPRNG values — 65536 is not a multiple
 * of 240, so a plain `% 240` would slightly favor the first 16 words.
 */

import { randomBytes } from './portable-crypto.js';

const WORDLIST = [
  'acid','arch','army','auto','axle','baby','back','bail','bake','balm',
  'band','bang','bank','barn','base','bath','beam','bean','bear','beat',
  'beef','bell','best','bike','bill','bird','bite','blob','blow','blue',
  'blur','bolt','bone','book','boom','bore','boss','both','bowl','buck',
  'bulb','bull','bump','burn','burp','buzz','cage','cake','calm','camp',
  'cape','card','care','carp','cart','case','cash','cast','cave','cell',
  'chad','chef','chip','city','clam','clap','clay','clip','club','clue',
  'coal','coat','coil','coin','cold','colt','comb','cone','cook','cool',
  'cope','cord','core','corn','cost','cozy','crab','crew','crop','crow',
  'cube','curb','cure','curl','damp','dare','dark','dart','dash','data',
  'date','dawn','dead','deal','dear','deck','deed','deep','deft','dell',
  'deny','desk','diet','dirt','dive','dock','dome','door','dose','dote',
  'dove','down','drag','draw','drip','drop','drum','duck','dull','dump',
  'dusk','dust','duty','each','earn','ease','east','echo','edge','epic',
  'even','exam','exit','face','fact','fade','fail','fair','fake','fall',
  'fame','farm','fast','fate','fawn','feel','feet','fell','felt','fern',
  'file','fill','film','find','fine','fire','firm','fish','fist','flag',
  'flat','flaw','flop','flow','foam','foil','fold','folk','fond','font',
  'food','foot','ford','fork','form','fort','foul','free','frog','from',
  'fuel','full','fume','fund','fuse','gale','game','gang','gate','gave',
  'gaze','gear','germ','gift','gill','give','glad','glen','glow','glue',
  'goal','goat','gold','golf','gone','good','grab','gram','gray','grew',
  'grid','grim','grip','grit','grow','gulf','gust','guts','half','hall',
  'halt','hand','hang','hard','harm','harp','hate','haul','hawk','haze',
];

const LIMIT = 65536 - (65536 % WORDLIST.length); // largest multiple of the list length

export function generatePassphrase(words = 9): string {
  if (words < 7) throw new Error('Minimum 7 words required (~55 bits with this 240-word list).');
  const result: string[] = [];
  while (result.length < words) {
    const buf = randomBytes((words - result.length) * 2);
    for (let i = 0; i + 1 < buf.length && result.length < words; i += 2) {
      const v = (buf[i] << 8) | buf[i + 1];
      if (v < LIMIT) result.push(WORDLIST[v % WORDLIST.length]);
    }
  }
  return result.join(' ');
}
