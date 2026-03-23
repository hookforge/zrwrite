extern int read_semantic_wide(void);

int main(void) {
    return read_semantic_wide() != 0x13572468;
}
