#ifndef SCYTALE_CORE_H
#define SCYTALE_CORE_H

#include <stddef.h>
#include <stdint.h>

/* ---- diagnostics ---------------------------------------------------------------------------- */

/* Known-answer and tamper checks. 0 = all passed, otherwise the first failed check. */
int32_t scytale_selftest(void);

/* Data Protection class applied to a probe file: 1 = Complete, -1 = simulator,
 * -2 = could not apply, -3 = bad path / I/O error. */
int32_t scytale_protection_probe(const uint8_t *dir, size_t len);

/* ---- core ------------------------------------------------------------------------------------
 * All calls must be serialised (one queue). Status codes only; display values are copied into
 * caller buffers which the caller wipes. Fields: 0 password, 1 confirm, 2 code, 3 recovery key. */

typedef struct ScyCore ScyCore;

ScyCore *scy_core_new(const uint8_t *dir, size_t len);
void scy_core_free(ScyCore *c);

/* Start notes: 0 needs setup, 1 none, 2 prev timeout, 3 prev background, 4 prev device lock,
 * 5 prev aborted, 6 lockout state reset (locked 15 min), 7 audit key missing, 8 prev capture. */
int32_t scy_core_start(ScyCore *c, const uint8_t *audit_key, size_t key_len, uint64_t *ts);
/* 0 setup, 1 login, 2 unlocked */
int32_t scy_phase(ScyCore *c);

int32_t scy_input_push(ScyCore *c, int32_t field, const uint8_t *utf8, size_t len);
void scy_input_backspace(ScyCore *c, int32_t field);
void scy_input_clear(ScyCore *c, int32_t field);
int32_t scy_input_count(ScyCore *c, int32_t field);

/* 0 ok, 1 weak password, 2 mismatch, 3 wrong state */
int32_t scy_setup_begin(ScyCore *c, int32_t recover);
int32_t scy_setup_qr(ScyCore *c, uint8_t *out, size_t cap);        /* width or -1 */
int32_t scy_setup_secret(ScyCore *c, uint8_t *out, size_t cap);    /* length or -1 */
int32_t scy_setup_pepper(ScyCore *c, uint8_t *out, size_t cap);    /* 32 or -1 */
int32_t scy_setup_pepper_verify(ScyCore *c, const uint8_t *p, size_t len); /* 1 ok */
int32_t scy_setup_code(ScyCore *c);                                /* 1 ok */
/* 0 ok, 1 not ready, 2 vault error, 3 audit error, 4 index error */
int32_t scy_setup_commit(ScyCore *c, const uint8_t *wrapped, size_t wrapped_len,
                         const uint8_t *audit_key, size_t key_len);
int32_t scy_setup_recovery_key(ScyCore *c, uint8_t *out, size_t cap); /* length or -1 */
void scy_setup_finish(ScyCore *c);
int32_t scy_recover_check(ScyCore *c);                             /* 1 ok */

int32_t scy_wrapped_pepper(ScyCore *c, uint8_t *out, size_t cap);  /* length or -1 */
uint64_t scy_locked_remaining(ScyCore *c);
/* 0 ok; 1 failed (aux = attempts left); 2 failed, now locked (aux = s); 3 locked (aux = s);
 * 4 incomplete; 5 audit unavailable; 6 index integrity failure; 7 vault terminated */
int32_t scy_login(ScyCore *c, const uint8_t *pepper, size_t len, uint64_t *aux);
/* 0 none; 1 = termination in 10 attempts; 2 = termination in 5 attempts */
int32_t scy_termination_level(ScyCore *c);

typedef struct {
    uint64_t last_login;
    uint32_t fails_since;
    int32_t chain;      /* 0 intact, 1 broken at chain_at, 2 truncated */
    uint64_t chain_at;
    uint32_t dropped;
    uint32_t shredded;
} ScySummary;
void scy_session_summary(ScyCore *c, ScySummary *out);

/* ---- vault contents (ids are 16 bytes) ---- */
int32_t scy_item_count(ScyCore *c);
/* kind 1 file, 2 message; returns name length or -1 */
int32_t scy_item_get(ScyCore *c, int32_t idx, uint8_t *id, int32_t *kind, uint64_t *created,
                     uint64_t *size, uint8_t *name, size_t cap);
/* 0 ok, 1 locked, 2 failed */
int32_t scy_import_file(ScyCore *c, const uint8_t *path, size_t len, uint8_t *out_id);
int32_t scy_import_bytes(ScyCore *c, const uint8_t *name, size_t name_len, const uint8_t *data,
                         size_t data_len, int32_t photo, uint8_t *out_id);
/* 0 ok; 1 failed (aux = attempts left); 2 locked out, session ended; 3 no session */
int32_t scy_reauth(ScyCore *c, const uint8_t *pepper, size_t len, uint64_t *aux);
/* 0 ok; 1 not authorised; 2 not found; 3 too large; 4 integrity failure; 5 no session; 6 message */
int32_t scy_view_open(ScyCore *c, const uint8_t *id, size_t *out_len);
int32_t scy_view_copy(ScyCore *c, uint8_t *out, size_t cap);
void scy_view_close(ScyCore *c);
int32_t scy_purge(ScyCore *c, const uint8_t *id); /* 1 ok */

/* ---- messages ---- */
int32_t scy_msg_seal(ScyCore *c, const uint8_t *text, size_t len); /* 1 ok */
/* after scy_reauth; destroyed on disk; read with scy_view_copy, then scy_view_close */
int32_t scy_msg_open(ScyCore *c, const uint8_t *id, size_t *out_len);

/* ---- audit / login log ---- */
int32_t scy_audit_load(ScyCore *c);
int32_t scy_audit_entry(ScyCore *c, int32_t i, uint64_t *seq, uint64_t *ts, uint64_t *extra,
                        uint8_t *ev, size_t cap);
int32_t scy_audit_chain(ScyCore *c, uint64_t *at);                  /* 0 ok, 1 broken, 2 truncated */

/* ---- courier (paired-device messages) ----
 * Courier errors (positive): 1 malformed, 2 bad signature, 3 unknown sender, 4 not verified,
 * 5 not paired, 6 already opened, 7 decrypt failed, 8 no one-time keys left, 9 too long,
 * 10 different device already paired, 11 own bundle. Negative: local errors (-4 = needs reauth). */
int32_t scy_courier_status(ScyCore *c, int32_t *paired, int32_t *verified, uint32_t *peer_keys, uint32_t *own_keys);
int32_t scy_courier_export_bundle(ScyCore *c);                         /* length in out buffer */
int32_t scy_courier_import_bundle(ScyCore *c, const uint8_t *data, size_t len, uint8_t *safety, size_t cap);
int32_t scy_courier_safety(ScyCore *c, uint8_t *out, size_t cap);
int32_t scy_courier_verify(ScyCore *c);
int32_t scy_courier_unpair(ScyCore *c);
int32_t scy_courier_send(ScyCore *c, const uint8_t *text, size_t len, int32_t burn, int32_t armored); /* length or -error */
int32_t scy_courier_out_copy(ScyCore *c, uint8_t *out, size_t cap);
int32_t scy_courier_receive(ScyCore *c, const uint8_t *data, size_t len, int32_t *burn, size_t *out_len);

/* ---- configuration (8 bytes: flags, timeout min, message min, originals policy) ----
 * flags bit0 custom (0 = hardened defaults), bit1 no lock on leave, bit2 code optional,
 * bit3 Face ID once per session, bit4 notifications off, bit5 screenshot warn only.
 * originals: 0 ask, 1 always delete, 2 always keep. */
int32_t scy_config_get(ScyCore *c, int32_t stored, uint8_t *out);
int32_t scy_config_begin(ScyCore *c);           /* after scy_reauth; 1 ok */
int32_t scy_config_set(ScyCore *c, const uint8_t *cfg); /* 1 ok */
void scy_config_end(ScyCore *c);
int32_t scy_reauth_required(ScyCore *c);

/* ---- tags (sealed in the vault; colours are palette indices 0..7) ----
 * scy_tags_get: "SCYT\x01", next u16, n u16, n * (id u16, color u8, len u8, name),
 *               m u32, m * (item[16], k u8, k * id u16). Little-endian. */
int32_t scy_tags_get(ScyCore *c, uint8_t *out, size_t cap);
int32_t scy_tag_create(ScyCore *c, const uint8_t *name, size_t len, uint8_t color); /* id > 0 */
int32_t scy_tag_update(ScyCore *c, uint16_t id, const uint8_t *name, size_t len, uint8_t color);
int32_t scy_tag_delete(ScyCore *c, uint16_t id);
int32_t scy_tag_set(ScyCore *c, const uint8_t *item, uint16_t id, int32_t on);

/* ---- diagnostics ---- */
int32_t scytale_provenance(uint8_t *out, size_t cap); /* provenance marker (Forenthal) */
uint64_t scytale_kdf_benchmark(uint32_t m_kib, uint32_t t, uint32_t p);
void scytale_kdf_default(uint32_t *m, uint32_t *t, uint32_t *p);

/* 0 logout, 1 timeout, 2 background, 3 device lock, 4 screen capture */
void scy_lock(ScyCore *c, int32_t reason);
/* 1 screenshot taken, 2 message expired, 3 message closed, 4 file re-encrypted (button), 5 file re-encrypted (automatic on lock) */
int32_t scy_audit_event(ScyCore *c, int32_t event);
int32_t scy_panic_wipe(ScyCore *c);

#endif
