import os #dosya yükleme
import hashlib
from flask import Flask, request, redirect, url_for, render_template, send_from_directory, flash
from werkzeug.utils import secure_filename
import pgpy

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'supersecretkey'

#dosya izin verilen uzantıda mı kontrol
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#pgp keyi oluşturma
def generate_key():
    key = pgpy.PGPKey.new(pgpy.constants.PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = pgpy.PGPUID.new('test', email='test@example.com') #kullanıcıya özel
    key.add_uid(uid, usage={pgpy.constants.KeyFlags.EncryptCommunications, pgpy.constants.KeyFlags.EncryptStorage},
                hashes=[pgpy.constants.HashAlgorithm.SHA256],
                ciphers=[pgpy.constants.SymmetricKeyAlgorithm.AES256],
                compression=[pgpy.constants.CompressionAlgorithm.ZLIB])
    return key

#pgp keyi ile şifreleme
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        message = pgpy.PGPMessage.new(f.read())
    encrypted_message = key.pubkey.encrypt(message)
    encrypted_file_path = f"{file_path}.pgp"
    with open(encrypted_file_path, 'wb') as f:
        f.write(bytes(encrypted_message))
    return encrypted_file_path

#pgp keyi ile decrypt etme
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_message = pgpy.PGPMessage.from_blob(f.read())
    decrypted_message = key.decrypt(encrypted_message)
    decrypted_file_path = file_path.replace('.pgp', '')
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_message.message)
    return decrypted_file_path

#hash
def hash_file(file_path, chunk_size=1024 * 1024):
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    sha512_hash = hashlib.sha512()

    chunk_hashes = []

    with open(file_path, 'rb') as f:
        chunk_index = 0
        while chunk := f.read(chunk_size): #parçaların degerleri
            chunk_md5 = hashlib.md5(chunk).hexdigest()
            chunk_sha256 = hashlib.sha256(chunk).hexdigest()
            chunk_sha512 = hashlib.sha512(chunk).hexdigest()
            
            chunk_hashes.append({
                'chunk_index': chunk_index,
                'md5': chunk_md5,
                'sha256': chunk_sha256,
                'sha512': chunk_sha512
            })

            md5_hash.update(chunk)
            sha256_hash.update(chunk)
            sha512_hash.update(chunk)

            chunk_index += 1

    file_hashes = { #dosyanın kendi degerleri
        'md5': md5_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest(),
        'sha512': sha512_hash.hexdigest()
    }

    return file_hashes, chunk_hashes

@app.route('/')
def upload_form():
    return render_template('upload.html')

#kullanıcıya gösterme
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('Dosya parçası yok')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('Seçilen dosya yok')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Dosyanın değerleri gösterme
        file_hashes, chunk_hashes = hash_file(file_path)
        print(f"Dosya SHA-512: {file_hashes['sha512']}")
        print(f"Dosya MD5: {file_hashes['md5']}")
        print(f"Dosya SHA-256: {file_hashes['sha256']}")

        # Parçanın değerleri gösterme
        for chunk_hash in chunk_hashes:
            print(f"Parça {chunk_hash['chunk_index']} MD5: {chunk_hash['md5']}")
            print(f"Parça {chunk_hash['chunk_index']} SHA-256: {chunk_hash['sha256']}")
            print(f"Parça {chunk_hash['chunk_index']} SHA-512: {chunk_hash['sha512']}")

        #PGP key gösterme
        key = generate_key()
        public_key = key.pubkey
        public_key_str = str(public_key)
        private_key_str = str(key)

        # şifrelenme çözüm ekran
        encrypted_file_path = encrypt_file(file_path, key)
        if encrypted_file_path:
            print("File encrypted successfully.")
        else:
            print("File encryption failed.")

        return render_template('result.html', file_hashes=file_hashes, chunk_hashes=chunk_hashes, encrypted_file=encrypted_file_path, public_key=public_key_str, private_key=private_key_str)
    else:
        flash('Invalid file format')
        return redirect(request.url)

#decrypt
@app.route('/decrypt', methods=['POST'])
def decrypt_uploaded_file():
    encrypted_file = request.form['encrypted_file']
    private_key_str = request.form['private_key']
    private_key = pgpy.PGPKey()
    private_key.parse(private_key_str)
    
    decrypted_file_path = decrypt_file(encrypted_file, private_key)
    if decrypted_file_path:
        return f"Dosya başarıyla decrypt edildi: {decrypted_file_path}"
    else:
        return "Decrypt başarısız oldu."

if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)
