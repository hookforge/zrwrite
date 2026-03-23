__attribute__((noinline)) static int branch_cold(int x) {
    return x + 11;
}

__attribute__((noinline)) int stripped_terminal_branch(int x) {
    if (x == 7) {
        return 29;
    }
    return branch_cold(x);
}

int main(void) {
    return stripped_terminal_branch(7) != 29;
}
