extern int read_semantic_prefix_interior_value(void);
extern int branch_to_semantic_prefix_interior_mid(void);

int main(void) {
    return read_semantic_prefix_interior_value() != 0x13579BDF ||
        branch_to_semantic_prefix_interior_mid() != 0x13579BDF;
}
