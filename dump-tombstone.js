const fs = require('fs');

const tombstone = process.argv[2];
if (!tombstone) {
  console.log('node dump-tombstone.js tombstone_00');
  process.exit(-1);
}

const text = fs.readFileSync(tombstone, 'utf8').split('\n');
const pc = text.filter(line => line.indexOf('pc') !== -1 && line.indexOf('cpsr') !== -1)[0].trim().replace(/ +/g, ' ').split(' ')[7];

let code = new Buffer(8000);
let pos = 0;
let in_code = false;
let start_addr = 0;
text.forEach(line => {
  if (!in_code) {
    if (line === 'code around pc:') {
      in_code = true;
    }
    return;
  }
  if (line.indexOf('    ') !== 0) {
    in_code = false;
    return;
  }
  line = line.trim().replace(/ +/g, ' ');
  line = line.substr(0, 44).split(' ').map(num => parseInt(num, 16));
  let addr = line[0];
  if (!start_addr) {
    start_addr = addr;
  }
  for (let i = 1; i < line.length; ++i) {
    let val = line[i];
    code.writeUInt32LE(val, pos);
    pos += 4;
  }
});
code = code.slice(0, pos);

console.log(code);

const capstone = require('capstone');
const cs = new capstone.Cs(capstone.ARCH_ARM, capstone.MODE_ARM);

cs.disasm(code, start_addr).forEach(function (insn) {
  let addr = insn.address.toString(16);
  let comment = '';
  if (addr === pc) {
    comment = ' <--';
  }
  console.log(insn.address.toString(16), insn.mnemonic, insn.op_str, comment);
});

cs.close();
