extern unsigned long long read_unsupported_semantic_interior_value(void);
extern unsigned long long branch_to_unsupported_semantic_interior_mid(void);

int main(void) {
    return read_unsupported_semantic_interior_value() != 0x1122334455667788ULL ||
        branch_to_unsupported_semantic_interior_mid() != 0x1122334455667788ULL;
}
