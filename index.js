class ASN1Decoder {
  constructor(data) {
    this.data = new Uint8Array(data);
    this.pos = 0;
    this.oids = [];
    this.oidMap = {
      "1.3.132.0.10": "ecdsa",
      "1.3.101.112": "ed25519",
      "1.2.840.10045.2.1": "pubkey",
    };
  }

  readLength() {
    let length = this.data[this.pos++];
    if (length & 0x80) {
      let numBytes = length & 0x7f;
      length = 0;
      for (let i = 0; i < numBytes; i++) {
        length = (length << 8) | this.data[this.pos++];
      }
    }
    return length;
  }

  readType() {
    return this.data[this.pos++];
  }

  readInteger() {
    let length = this.readLength();
    let value = 0;
    for (let i = 0; i < length; i++) {
      value = (value << 8) | this.data[this.pos++];
    }
    return { integer: value };
  }

  readOctetString() {
    let length = this.readLength();
    let value = this.data.slice(this.pos, this.pos + length);
    this.pos += length;
    return { pkey: value };
  }

  readBitString() {
    let length = this.readLength();
    let unusedBits = this.data[this.pos++]; // First byte indicates the number of unused bits
    let value = this.data.slice(this.pos, this.pos + length - 1);
    this.pos += length - 1;
    return { unusedBits, pubkey: value };
  }

  readObjectIdentifier() {
    let length = this.readLength();
    let endPos = this.pos + length;
    let oid = [];
    let value = 0;

    // The first byte contains the first two components
    let firstByte = this.data[this.pos++];
    oid.push(Math.floor(firstByte / 40));
    oid.push(firstByte % 40);

    while (this.pos < endPos) {
      let byte = this.data[this.pos++];
      value = (value << 7) | (byte & 0x7f);
      if (!(byte & 0x80)) {
        oid.push(value);
        value = 0;
      }
    }

    let oidStr = oid.join(".");
    this.oids.push(oidStr);
    return { oid: oidStr }; // Return OID as a string
  }

  getOids() {
    return this.oids;
  }

  getOidKeyTypes() {
    return this.oids.map((oid) => this.oidMap[oid] || "unknown");
  }

  readSequence() {
    let length = this.readLength();
    let endPos = this.pos + length;
    let items = []; // this would better be map or obj
    while (this.pos < endPos) {
      items.push(this.read());
    }
    return items;
  }

  read() {
    let type = this.readType();
    switch (type) {
      case 0x02: // INTEGER
        return this.readInteger();
      case 0x03: // BIT STRING FOR PUBKEY
        return this.readBitString();
      case 0x04: // OCTET STRING FOR PKEY
        return this.readOctetString();
      case 0x06: // OBJECT IDENTIFIER FOR CURVE TYPE
        return this.readObjectIdentifier();
      case 0x30: // SEQUENCE
        return this.readSequence();
      case 0xa0: // NODE TAG COULD BE TREATED AS SEQUENCE
        return this.readSequence();
      case 0xa1: // NODE TAG COULD BE TREATED AS SEQUENCE
        return this.readSequence();
      default:
        throw new Error("Unsupported type: " + type);
    }
  }
}

// Example usage:
const data1 = Uint8Array.from(
  Buffer.from(
    "302e020100300506032b657004220420feb858a4a69600a5eef2d9c76f7fb84fc0b6627f29e0ab17e160f640c267d404",
    "hex"
  )
);

let decoder = new ASN1Decoder(data1);
let result = decoder.read();

console.log("Full ASN1 decode: \n", result, "\n");
console.log("Decoded oids: \n", decoder.getOids(), "\n");
console.log("Oid key types: \n", decoder.getOidKeyTypes(), "\n");

const data2 = Uint8Array.from(
  Buffer.from(
    "302a300506032b65700321008ccd31b53d1835b467aac795dab19b274dd3b37e3daf12fcec6bc02bac87b53d",
    "hex"
  )
);

decoder = new ASN1Decoder(data2);
result = decoder.read();

console.log("Full ASN1 decode: \n", result, "\n");
console.log("Decoded oids: \n", decoder.getOids(), "\n");
console.log("Oid key types: \n", decoder.getOidKeyTypes(), "\n");

const data3 = Uint8Array.from(
  Buffer.from(
    "3030020100300706052b8104000a042204208c2cdc9575fe67493443967d74958fd7808a3787fd3337e99cfeebbc7566b586",
    "hex"
  )
);

decoder = new ASN1Decoder(data3);
result = decoder.read();

console.log("Full ASN1 decode: \n", result, "\n");
console.log("Decoded oids: \n", decoder.getOids(), "\n");
console.log("Oid key types: \n", decoder.getOidKeyTypes(), "\n");

const data4 = Uint8Array.from(
  Buffer.from(
    "302d300706052b8104000a032200028173079d2e996ef6b2d064fc82d5fc7094367211e28422bec50a2f75c365f5fd",
    "hex"
  )
);

decoder = new ASN1Decoder(data4);
result = decoder.read();

console.log("Full ASN1 decode: \n", result, "\n");
console.log("Decoded oids: \n", decoder.getOids(), "\n");
console.log("Oid key types: \n", decoder.getOidKeyTypes(), "\n");

const data5 = Uint8Array.from(
  Buffer.from(
    "30540201010420ac318ea8ff8d991ab2f16172b4738e74dc35a56681199cfb1c0cb2e7cb560ffda00706052b8104000aa124032200036843f5cb338bbb4cdb21b0da4ea739d910951d6e8a5f703d313efe31afe788f4",
    "hex"
  )
);

decoder = new ASN1Decoder(data5);
result = decoder.read();

console.log("Full ASN1 decode: \n", result, "\n");
console.log("Decoded oids: \n", decoder.getOids(), "\n");
console.log("Oid key types: \n", decoder.getOidKeyTypes(), "\n");

const data6 = Uint8Array.from(
  Buffer.from(
    "3036301006072a8648ce3d020106052b8104000a032200036843f5cb338bbb4cdb21b0da4ea739d910951d6e8a5f703d313efe31afe788f4",
    "hex"
  )
);

decoder = new ASN1Decoder(data6);
result = decoder.read();

console.log("Full ASN1 decode: \n", result, "\n");
console.log("Decoded oids: \n", decoder.getOids(), "\n");
console.log("Oid key types: \n", decoder.getOidKeyTypes(), "\n");

const data7 = Uint8Array.from(
  Buffer.from(
    "307402010104208927647ad12b29646a1d051da8453462937bb2c813c6815cac6c0b720526ffc6a00706052b8104000aa14403420004aaac1c3ac1bea0245b8e00ce1e2018f9eab61b6331fbef7266f2287750a6597795f855ddcad2377e22259d1fcb4e0f1d35e8f2056300c15070bcbfce3759cc9d",
    "hex"
  )
);

decoder = new ASN1Decoder(data7);
result = decoder.read();

console.log("Full ASN1 decode: \n", result, "\n");
console.log("Decoded oids: \n", decoder.getOids(), "\n");
console.log("Oid key types: \n", decoder.getOidKeyTypes(), "\n");

const data8 = Uint8Array.from(
  Buffer.from(
    "3056301006072a8648ce3d020106052b8104000a03420004aaac1c3ac1bea0245b8e00ce1e2018f9eab61b6331fbef7266f2287750a6597795f855ddcad2377e22259d1fcb4e0f1d35e8f2056300c15070bcbfce3759cc9d",
    "hex"
  )
);

decoder = new ASN1Decoder(data8);
result = decoder.read();

console.log("Full ASN1 decode: \n", result, "\n");
console.log("Decoded oids: \n", decoder.getOids(), "\n");
console.log("Oid key types: \n", decoder.getOidKeyTypes(), "\n");

const data9 = Uint8Array.from(
  Buffer.from(
    "302e0201010420a6170a6aa6389a5bd3a3a8f9375f57bd91aa7f7d8b8b46ce0b702e000a21a5fea00706052b8104000a",
    "hex"
  )
);

decoder = new ASN1Decoder(data9);
result = decoder.read();

console.log("Full ASN1 decode: \n", result, "\n");
console.log("Decoded oids: \n", decoder.getOids(), "\n");
console.log("Oid key types: \n", decoder.getOidKeyTypes(), "\n");
