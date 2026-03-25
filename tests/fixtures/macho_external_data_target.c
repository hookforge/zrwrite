#include <stdint.h>

uint64_t target_value = 41;

extern uint64_t macho_external_data_patchpoint(void);

int main(void) {
    return macho_external_data_patchpoint() == 42u ? 0 : 1;
}
