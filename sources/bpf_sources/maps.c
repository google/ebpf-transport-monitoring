// This file is needed to load shared maps first. We can load this bpf file
// first. Then in other bpf files that may or may not need this we
// can simply reuse the maps created.

#include "maps.h"
