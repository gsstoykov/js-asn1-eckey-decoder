class ASN1Decoder {
    constructor(data) {
        this.data = new Uint8Array(data);
        this.pos = 0;
    }

    readLength() {
        let length = this.data[this.pos++];
        if (length & 0x80) {
            let numBytes = length & 0x7F;
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
        return value;
    }

    readOctetString() {
        let length = this.readLength();
        let value = this.data.slice(this.pos, this.pos + length);
        this.pos += length;
        return value;
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
            value = (value << 7) | (byte & 0x7F);
            if (!(byte & 0x80)) {
                oid.push(value);
                value = 0;
            }
        }

        return oid.join('.');
    }

    readSequence() {
        let length = this.readLength();
        let endPos = this.pos + length;
        let items = [];
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
            case 0x04: // OCTET STRING
                return this.readOctetString();
            case 0x06: // OBJECT IDENTIFIER
                return this.readObjectIdentifier();
            case 0x30: // SEQUENCE
                return this.readSequence();
            default:
                throw new Error("Unsupported type: " + type);
        }
    }
}

// Example usage:

// Sample DER-encoded data for a sequence containing an integer, an object identifier, and an octet string
const data = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20, 0xfe, 0xb8, 0x58, 0xa4, 0xa6, 0x96, 0x00, 0xa5,
    0xee, 0xf2, 0xd9, 0xc7, 0x6f, 0x7f, 0xb8, 0x4f, 0xc0, 0xb6, 0x62, 0x7f,
    0x29, 0xe0, 0xab, 0x17, 0xe1, 0x60, 0xf6, 0x40, 0xc2, 0x67, 0xd4, 0x04
]);

const decoder = new ASN1Decoder(data);
const result = decoder.read();

console.log(result);
