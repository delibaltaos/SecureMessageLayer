/**
* @file sml.h
 * @brief Secure Messaging Layer (SML) main header file
 *
 * This header file defines the core structures and functions for the Secure Messaging Layer (SML) library.
 * SML provides both pairwise (Double Ratchet) and group (MLS) secure messaging capabilities.
 *
 * @author [Deli Balta]
 * @date [02 Aug 2024]
 */

#ifndef SML_H
#define SML_H

#include <stdint.h>
#include <stddef.h>

/**
 * @struct pairwise_session_t
 * @brief Opaque structure representing a pairwise (Double Ratchet) session
 */
typedef struct pairwise_session_t pairwise_session;

/**
 * @struct group_session_t
 * @brief Opaque structure representing a group (MLS) session
 */
typedef struct group_session_t group_session;

/**
 * @struct prekey_bundle
 * @brief Structure representing a pre-key bundle for X3DH protocol
 *
 * This structure contains all the necessary components for initiating
 * a secure session using the X3DH (Extended Triple Diffie-Hellman) protocol.
 */
typedef struct {
 /**
  * @brief User's long-term identity public key
  */
 unsigned char identity_key[32];

 /**
  * @brief User's signed pre-key
  */
 unsigned char signed_prekey[32];

 /**
  * @brief Signature of the signed pre-key
  */
 unsigned char signed_prekey_signature[64];

 /**
  * @brief One-time pre-key (may be NULL if all one-time pre-keys are exhausted)
  */
 unsigned char one_time_prekey[32];

 /**
  * @brief Flag indicating whether a one-time pre-key is included
  * 1 if one-time pre-key is present, 0 otherwise
  */
 int has_one_time_prekey;

 /**
  * @brief Pre-key identifier
  */
 uint32_t prekey_id;

} prekey_bundle;

/**
 * @brief Initializes a new pairwise session
 *
 * This function initializes a new pairwise session using the Double Ratchet algorithm.
 * It generates a new session object and sets up the initial keys using the provided public key.
 *
 * @param[out] session Pointer to a pairwise_session pointer that will be set to the newly generated session
 * @param[in] their_public_key The public key of the other party
 * @param[in] their_public_key_len The length of the other party's public key
 * @return 0 on success, or a negative error code on failure
 *
 * @note The caller is responsible for freeing the session object when it's no longer needed.
 */
int pairwise_init_session(pairwise_session **session,
                          const unsigned char *their_public_key,
                          size_t their_public_key_len);

int pairwise_destroy_session(pairwise_session *session);

/**
 * @brief Retrieves the user's current pre-key bundle for X3DH
 *
 * This function retrieves the current pre-key bundle for the user.
 * The pre-key bundle contains the necessary components for others to initiate a secure session with this user.
 * The module automatically manages and regenerates pre-keys as needed.
 *
 * @param[out] own_prekey_bundle Pointer to store the user's current pre-key bundle
 * @return 0 on success, or a negative error code on failure
 */
int x3dh_get_own_prekey_bundle(prekey_bundle *own_prekey_bundle);

/**
 * @brief Encrypts data using the pairwise session
 *
 * This function encrypts data using the current state of the pairwise session.
 * It automatically updates the session state as per the Double Ratchet algorithm.
 *
 * @param[in] session The pairwise session to use for encryption
 * @param[in] data The data to encrypt
 * @param[in] data_len The length of the input data
 * @param[out] encrypted_data Buffer to store the encrypted data
 * @param[in,out] encrypted_data_len On input, the size of the encrypted_data buffer. On output, the actual length of the encrypted data.
 * @return 0 on success, or a negative error code on failure
 */
int pairwise_encrypt(pairwise_session *session,
                     const unsigned char *data,
                     size_t data_len,
                     unsigned char *encrypted_data,
                     size_t *encrypted_data_len);

/**
 * @brief Decrypts data using the pairwise session
 *
 * This function decrypts data using the current state of the pairwise session.
 * It automatically updates the session state as per the Double Ratchet algorithm.
 *
 * @param[in] session The pairwise session to use for decryption
 * @param[in] encrypted_data The encrypted data to decrypt
 * @param[in] encrypted_data_len The length of the encrypted data
 * @param[out] decrypted_data Buffer to store the decrypted data
 * @param[in,out] decrypted_data_len On input, the size of the decrypted_data buffer. On output, the actual length of the decrypted data.
 * @return 0 on success, or a negative error code on failure
 */
int pairwise_decrypt(pairwise_session *session,
                     const unsigned char *encrypted_data,
                     size_t encrypted_data_len,
                     unsigned char *decrypted_data,
                     size_t *decrypted_data_len);

#endif //SML_H