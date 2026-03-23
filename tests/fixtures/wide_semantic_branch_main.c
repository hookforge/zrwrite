extern int read_semantic_branch_value(void);
extern int branch_to_semantic_branch_mid(void);

int main(void) {
    return read_semantic_branch_value() != 0x24681357 ||
        branch_to_semantic_branch_mid() != 0x24681357;
}
