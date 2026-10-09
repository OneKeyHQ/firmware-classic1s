#ifndef __COIN_PARSER_STATE_H__
#define __COIN_PARSER_STATE_H__

/* The concrete union is private so independent parser namespaces stay local. */
void *coin_parser_state_cosmos(void);
void *coin_parser_state_algorand(void);
void *coin_parser_state_filecoin(void);
void coin_parser_state_clear(void);

#endif /* __COIN_PARSER_STATE_H__ */
