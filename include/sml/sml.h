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
 * @brief Initializes a new pairwise session
 *
 * This function initializes a new pairwise session using the Double Ratchet algorithm.
 * It creates a new session object and sets up the initial keys using the provided public key.
 *
 * @param[out] session Pointer to a pairwise_session pointer that will be set to the newly created session
 * @param[in] their_public_key The public key of the other party
 * @param[in] their_public_key_len The length of the other party's public key
 * @return 0 on success, or a negative error code on failure
 *
 * @note The caller is responsible for freeing the session object when it's no longer needed.
 */
int pairwise_init_session(pairwise_session **session,
                          const unsigned char *their_public_key,
                          size_t their_public_key_len);

#endif //SML_H