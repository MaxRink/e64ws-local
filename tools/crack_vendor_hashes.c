/*
 * Offline checker for the password verifier embedded in checkLogin.php.
 *
 * This deliberately accepts candidates from stdin and never contacts a
 * grinder or a network service. It is included for owner-authorized recovery
 * of the static verifiers found in the supplied firmware image.
 *
 * Build on macOS with Homebrew OpenSSL 3.0 or newer (EVP_MD_fetch requires
 * 3.0):
 *   clang -O3 -I/opt/homebrew/include -L/opt/homebrew/lib \
 *     -o /tmp/e64ws-crack tools/crack_vendor_hashes.c -lcrypto
 *
 * Usage:
 *   /tmp/e64ws-crack < candidates.txt
 *   /tmp/e64ws-crack --self-test
 *   /tmp/e64ws-crack --help
 *
 * Candidates are read from stdin, one per line. Empty lines are skipped, so
 * an empty password cannot be tested through this path.
 */
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *name;
    unsigned rounds;
    const char *salt;
    const char *expected;
} verifier_t;

static const verifier_t verifiers[] = {
    {"MobileApp", 10000, "eZFQmMt4eq9HXow3", "BgLkj95Jl0Ez+wjXcfH1+FDfeGWLr1tY+dzGERjhbO0"},
    {"Developer", 5000, "g+oHbi70m6JlITUt", "1uXsbsm7qgeCMA6KaLRI0IllvvNK6Pqy91h0tFNr7Bk"},
    {"NG2-Technician", 5000, "xqk93F93UpNIK7z2", "rgn+4O3cX4Rw9zr/vIqQMmH45L+ptTNueLUotiGpeyM"},
    {"NG2-Owner", 5000, "+PDgaaRbD6jGowEL", "nLehOmftBPM885XIxZ5pT9zGk6C12G2++8IzSNGdRq0"}
};

static const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode_no_padding(const unsigned char *in, size_t len,
                                    char *out, size_t out_len) {
    size_t i = 0, j = 0;
    while (i + 2 < len) {
        if (j + 4 >= out_len) return 0;
        out[j++] = alphabet[(in[i] >> 2) & 63];
        out[j++] = alphabet[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
        out[j++] = alphabet[((in[i + 1] & 15) << 2) | (in[i + 2] >> 6)];
        out[j++] = alphabet[in[i + 2] & 63];
        i += 3;
    }
    if (i < len) {
        if (j + 4 >= out_len) return 0;
        out[j++] = alphabet[(in[i] >> 2) & 63];
        if (i + 1 == len) {
            out[j++] = alphabet[(in[i] & 3) << 4];
        } else {
            out[j++] = alphabet[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
            out[j++] = alphabet[(in[i + 1] & 15) << 2];
        }
    }
    out[j] = '\0';
    return j;
}

/* Returns 1 on a match, 0 on a mismatch, -1 when the digest cannot be
   computed (allocation or EVP failure), and reports failures on stderr. */
static int candidate_matches(const char *password, const verifier_t *v) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    EVP_MD *md;
    EVP_MD_CTX *ctx;
    char encoded[128];
    size_t pw_len = strlen(password);
    size_t salt_len = strlen(v->salt);
    size_t digest_len;
    size_t base_len;
    int result = -1;

    /* The salt is copied into digest[] for the first round. Verifier salts are
       16 bytes by format, so a longer one is a broken table entry. */
    if (salt_len > sizeof(digest)) {
        fprintf(stderr, "crack_vendor_hashes: salt for %s is longer than %zu bytes\n",
                v->name, sizeof(digest));
        return -1;
    }

    /* Fetch once and reuse. An implicit EVP_sha256() fetch on every round
       roughly doubles the run time of this loop. Check the size because a
       non-default provider could return a different digest length. */
    md = EVP_MD_fetch(NULL, "SHA2-256", NULL);
    if (md == NULL) {
        fprintf(stderr, "crack_vendor_hashes: cannot fetch SHA-256 for %s\n",
                v->name);
        return -1;
    }
    if (EVP_MD_get_size(md) != SHA256_DIGEST_LENGTH) {
        fprintf(stderr, "crack_vendor_hashes: fetched SHA-256 reports a %d-byte "
                "digest for %s\n", EVP_MD_get_size(md), v->name);
        EVP_MD_free(md);
        return -1;
    }
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "crack_vendor_hashes: cannot allocate a digest context "
                "for %s\n", v->name);
        EVP_MD_free(md);
        return -1;
    }

    /* PHP starts with the ASCII salt itself, not with a pre-hashed seed: the
       running value is salt || password || salt || value for the first round
       and binary digest || password || salt || binary digest afterwards. */
    memcpy(digest, v->salt, salt_len);
    digest_len = salt_len;
    for (unsigned round = 0; round < v->rounds; ++round) {
        /* EVP_DigestFinal_ex only writes after the reads above, so the in-place
           digest buffer is safe here. */
        if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
            EVP_DigestUpdate(ctx, digest, digest_len) != 1 ||
            EVP_DigestUpdate(ctx, password, pw_len) != 1 ||
            EVP_DigestUpdate(ctx, v->salt, salt_len) != 1 ||
            EVP_DigestUpdate(ctx, digest, digest_len) != 1 ||
            EVP_DigestFinal_ex(ctx, digest, NULL) != 1) {
            goto out;
        }
        digest_len = sizeof(digest);
    }

    base_len = b64_encode_no_padding(digest, digest_len, encoded,
                                     sizeof(encoded));
    result = base_len != 0 && strcmp(encoded, v->expected) == 0;
out:
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    if (result < 0) {
        fprintf(stderr, "crack_vendor_hashes: hashing failed for %s\n", v->name);
    }
    return result;
}

/* Synthetic reference vectors for the documented construction, derived with
   Python hashlib. They are not vendor verifier material. The one-round vector
   is pwhash("p", "a", 1), published in docs/FLAWS.md; the ten-round vector is
   a synthetic reference that also pins the switch from hashing the salt
   length on round 0 to hashing the 32-byte digest afterwards. */
static const verifier_t self_test_vectors[] = {
    {"self-test-r1", 1, "a", "O/cjYcZvUlm+W5/SulXxepXK3dYd93iccPKHwYxy4Is"},
    {"self-test-r10", 10, "a", "lJ/Ro2oNltI1LN0G0qfPb0zK1saDMOLv3zd70n4Hm70"}
};

static int run_self_test(void) {
    for (size_t i = 0; i < sizeof(self_test_vectors) / sizeof(self_test_vectors[0]);
         ++i) {
        const verifier_t *v = &self_test_vectors[i];
        int positive = candidate_matches("p", v);
        if (positive < 0) {
            fprintf(stderr, "self-test FAIL: hashing error for %s\n", v->name);
            return 1;
        }
        if (positive == 0) {
            fprintf(stderr, "self-test FAIL: %s did not reproduce its reference "
                    "digest\n", v->name);
            return 1;
        }
        int negative = candidate_matches("not-p", v);
        if (negative < 0) {
            fprintf(stderr, "self-test FAIL: hashing error for %s\n", v->name);
            return 1;
        }
        if (negative != 0) {
            fprintf(stderr, "self-test FAIL: %s reported a non-matching candidate "
                    "as a match\n", v->name);
            return 1;
        }
    }
    puts("self-test OK");
    return 0;
}

static void print_usage(FILE *out) {
    fputs("usage: crack_vendor_hashes [--self-test | --help]\n"
          "  Reads candidate passwords from stdin, one per line, and prints\n"
          "  FOUND <verifier> <candidate> for each match. Empty lines are\n"
          "  skipped, so an empty password cannot be tested this way.\n"
          "  --self-test  check the hash construction against reference vectors\n"
          "  -h, --help   show this message\n"
          "exit status: 0 success, 1 hashing or self-test failure, 2 usage error\n",
          out);
}

int main(int argc, char **argv) {
    char line[1024];
    unsigned long candidates = 0;

    if (argc > 1) {
        const char *arg = argv[1];
        int self_test = strcmp(arg, "--self-test") == 0;
        int help = strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0;

        if ((self_test || help) && argc > 2) {
            fprintf(stderr, "crack_vendor_hashes: unexpected argument after %s: %s\n",
                    arg, argv[2]);
            print_usage(stderr);
            return 2;
        }
        if (self_test) {
            return run_self_test();
        }
        if (help) {
            print_usage(stdout);
            return 0;
        }
        fprintf(stderr, "crack_vendor_hashes: unknown argument: %s\n", arg);
        print_usage(stderr);
        return 2;
    }
    while (fgets(line, sizeof(line), stdin) != NULL) {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;
        ++candidates;
        for (size_t i = 0; i < sizeof(verifiers) / sizeof(verifiers[0]); ++i) {
            int match = candidate_matches(line, &verifiers[i]);
            if (match < 0) return 1;
            if (match) {
                printf("FOUND %s %s\n", verifiers[i].name, line);
                fflush(stdout);
            }
        }
    }
    fprintf(stderr, "checked %lu candidates\n", candidates);
    return 0;
}
