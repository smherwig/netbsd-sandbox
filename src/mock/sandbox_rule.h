#ifndef _SANDBOX_RULE_H_
#define _SANDBOX_RULE_H_

#define SANDBOX_RULE_MAXNAMELEN 32      /* includes null */
#define SANDBOX_RULE_MAXNAMES 3

struct sandbox_rule {
    const char *names[SANDBOX_RULE_MAXNAMES];
};

#define SANDBOX_RULE_SCOPE(rule)       ((rule)->names[0])
#define SANDBOX_RULE_ACTION(rule)      ((rule)->names[1])
#define SANDBOX_RULE_SUBACTION(rule)   ((rule)->names[2])

#define SANDBOX_RULE_MAKE(rule, scope, action, subaction) \
    do { \
        (rule)->names[0] = scope; \
        (rule)->names[1] = action; \
        (rule)->names[2] = subaction; \
    } while (0)

int sandbox_rule_isvnode(const struct sandbox_rule *rule);
int sandbox_rule_size(const struct sandbox_rule *rule);
int sandbox_rule_initfromstring(const char *s, struct sandbox_rule *rule);
void sandbox_rule_freenames(struct sandbox_rule *rule);

#endif /* !_SANDBOX_RULE_H_*/
