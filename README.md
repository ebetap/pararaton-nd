Untuk menguji tingkat keamanan dari metode enkripsi dan dekripsi menggunakan algoritma AES-GCM dan RSA-OAEP, kita perlu memahami konsep dasar dan mengukur kekuatan kriptografis dari algoritma yang digunakan.

### AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)
1. **Keamanan AES**:
    - AES adalah standar enkripsi simetris yang banyak digunakan dan sangat aman.
    - AES-256 (menggunakan kunci 256-bit) memberikan tingkat keamanan yang sangat tinggi.
    - Saat ini, tidak ada serangan praktis yang dapat mematahkan enkripsi AES-256 dalam waktu yang wajar.

2. **Keamanan GCM**:
    - GCM adalah mode operasi untuk AES yang menawarkan kecepatan tinggi dan keamanan tambahan dalam bentuk autentikasi.
    - GCM menyediakan integritas data selain kerahasiaan, melindungi data dari manipulasi.

### RSA-OAEP (Rivest-Shamir-Adleman - Optimal Asymmetric Encryption Padding)
1. **Keamanan RSA**:
    - RSA adalah algoritma enkripsi asimetris yang sangat aman ketika digunakan dengan panjang kunci yang cukup.
    - Umumnya, panjang kunci RSA minimal 2048-bit digunakan untuk mencapai keamanan yang baik.

2. **Keamanan OAEP**:
    - OAEP adalah skema padding yang meningkatkan keamanan RSA dengan melindungi terhadap serangan tertentu seperti serangan padding oracle.
    - OAEP menggunakan hash function (seperti SHA-256) untuk memberikan keamanan tambahan.

### Pengujian Keamanan
Untuk menguji keamanan secara praktis, kita perlu melakukan beberapa langkah:

1. **Analisis Kriptografis Teoretis**:
    - Menggunakan algoritma yang telah diakui aman oleh komunitas kriptografi.
    - Memastikan panjang kunci yang digunakan cukup untuk mencegah serangan brute force.

2. **Pengujian Praktis**:
    - Mengukur performa enkripsi dan dekripsi.
    - Memastikan tidak ada kebocoran informasi melalui side-channel attacks (seperti analisis waktu atau konsumsi daya).

### Pengujian Praktis di Node.js

Kita dapat melakukan beberapa pengujian dasar untuk memastikan bahwa enkripsi dan dekripsi bekerja dengan benar dan tidak ada data yang hilang atau rusak selama proses tersebut. Pengujian ini tidak akan mengukur keamanan kriptografis secara mendalam tetapi akan memastikan implementasi kita bekerja dengan benar.

```javascript
const crypto = require('crypto');

// Fungsi untuk menghasilkan pasangan kunci RSA
function generateRSAKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
        },
    });
}

// Fungsi untuk mengenkripsi data menggunakan AES-GCM
function encryptDataWithAESGCM(data, aesKey) {
    const iv = crypto.randomBytes(12); // AES-GCM memerlukan IV sepanjang 12 byte
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);

    const encryptedData = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
        iv: iv.toString('hex'),
        data: encryptedData.toString('hex'),
        authTag: authTag.toString('hex'),
    };
}

// Fungsi untuk mendekripsi data menggunakan AES-GCM
function decryptDataWithAESGCM(encryptedData, aesKey, iv, authTag) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    const decryptedData = Buffer.concat([
        decipher.update(Buffer.from(encryptedData, 'hex')),
        decipher.final(),
    ]);

    return decryptedData.toString('utf8');
}

// Fungsi untuk mengenkripsi kunci AES menggunakan RSA-OAEP
function encryptAESKeyWithRSA(aesKey, publicKey) {
    return crypto.publicEncrypt(
        {
            key: publicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        aesKey
    ).toString('hex');
}

// Fungsi untuk mendekripsi kunci AES menggunakan RSA-OAEP
function decryptAESKeyWithRSA(encryptedAESKey, privateKey) {
    return crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        Buffer.from(encryptedAESKey, 'hex')
    );
}

// Contoh penggunaan
const { publicKey, privateKey } = generateRSAKeyPair();
const aesKey = crypto.randomBytes(32); // AES-256 membutuhkan kunci sepanjang 32 byte

const data = 'Hello, World!';
const encrypted = encryptDataWithAESGCM(data, aesKey);
const decrypted = decryptDataWithAESGCM(encrypted.data, aesKey, encrypted.iv, encrypted.authTag);

console.log('Data:', data);
console.log('Encrypted Data:', encrypted);
console.log('Decrypted Data:', decrypted);

const encryptedAESKey = encryptAESKeyWithRSA(aesKey, publicKey);
const decryptedAESKey = decryptAESKeyWithRSA(encryptedAESKey, privateKey);

console.log('AES Key:', aesKey.toString('hex'));
console.log('Encrypted AES Key:', encryptedAESKey);
console.log('Decrypted AES Key:', decryptedAESKey.toString('hex'));

// Validasi bahwa dekripsi kunci AES menghasilkan kunci yang sama dengan aslinya
console.log('AES Key Match:', aesKey.equals(decryptedAESKey));

// Validasi bahwa data asli sama dengan data yang telah didekripsi
console.log('Data Match:', data === decrypted);
```

### Kesimpulan

Dengan menjalankan skrip di atas, Anda dapat memvalidasi bahwa:

1. Data yang dienkripsi menggunakan AES-GCM dapat didekripsi kembali dengan benar.
2. Kunci AES yang dienkripsi menggunakan RSA-OAEP dapat didekripsi kembali dengan benar.
3. Tidak ada kebocoran atau kerusakan data selama proses enkripsi dan dekripsi.

### Catatan:
- Untuk pengujian lebih lanjut, Anda dapat menggunakan alat kriptografi khusus dan melakukan analisis keamanan yang lebih mendalam.
- Keamanan sebenarnya dari sistem ini bergantung pada praktik keamanan yang baik, termasuk perlindungan kunci, implementasi yang aman, dan penggunaan panjang kunci yang cukup.
