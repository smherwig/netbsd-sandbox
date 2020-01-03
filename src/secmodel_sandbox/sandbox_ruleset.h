#ifndef _SANDBOX_RULESET_H_
#define _SANDBOX_RULESET_H_

#include <sys/queue.h>

#include "sandbox_path.h"
#include "sandbox_ref.h"
#include "sandbox_rule.h"

/* struct sandbox_rulelist {   }; */
TAILQ_HEAD(sandbox_rulelist, sandbox_rulenode);

#define SANDBOX_RULETYPE_NONE       (0L)
#define SANDBOX_RULETYPE_TRILEAN    (1L << 0)
#define SANDBOX_RULETYPE_WHITELIST  (1L << 1)
#define SANDBOX_RULETYPE_BLACKLIST  (1L << 2)
#define SANDBOX_RULETYPE_FUNCTION   (1L << 3)

struct sandbox_rulenode {
    char name[SANDBOX_RULE_MAXNAMELEN];
    int type;
    int level;
    int  value;     /* KAUTH_RESULT_{ALLOW,DENY,DEFER} */
    struct sandbox_path_list whitelist;
    struct sandbox_path_list blacklist;
    struct sandbox_ref_list     funclist;
    TAILQ_ENTRY(sandbox_rulenode) node_next; /* link for sibling list; */
    struct sandbox_rulelist children;
};

struct sandbox_ruleset {
    /* TODO: include lock */
    struct sandbox_rulenode *root;
};

struct sandbox_ruleset * sandbox_ruleset_create(int allow);

int sandbox_ruleset_insert(struct sandbox_ruleset *set,
        const struct sandbox_rule *rule, int type,
        int value, struct sandbox_path_list *paths);

const struct sandbox_rulenode *
sandbox_ruleset_search(const struct sandbox_ruleset *set,
        const struct sandbox_rule *rule);

void sandbox_ruleset_destroy(struct sandbox_ruleset *set);

#endif /* !_SANDBOX_RULESET_H_ */
