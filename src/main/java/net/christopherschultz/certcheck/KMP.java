package net.christopherschultz.certcheck;

/**
 * An implementation of the Knuth-Morris-Pratt algorithm
 * {@link https://en.wikipedia.org/wiki/Knuth%E2%80%93Morris%E2%80%93Pratt_algorithm}
 * @author Christopher Schultz
 * @author https://stackoverflow.com/a/25659067/276232
 *
 * I've made some (hopeful) improvements to the KMP implementation.
 */
class KMP {
    /**
     * Returns the first index of the occurrence of the byte array
     * <code>needles</code> within the <code>haystack</code> array, with the
     * same bytes, in the same order, start-to-finish.
     *
     * @param haystack The array to search <i>in</i>.
     * @param needles The array to search <i>for</i>.
     *
     * @return The index first array index at which <code>needles</code>
     * can be found within <code>haystack</code>, or <code>-1</code> if
     * <code>needles</code> does not appear within <code>haystack</code>.
     */
    public static int indexOf(byte[] haystack, byte[] needles) {
        if(null == haystack || null == needles) {
            return -1;
        }

        final int plen = needles.length;
        final int dlen = haystack.length;

        if(dlen < plen) {
            // Can't possibly find a large array in a small one
            return -1;
        } else if(0 == plen) {
            // Found it!
            return 0;
        } else if(0 == dlen) {
            // Not going to find it
            return -1;
        }

        int[] failure = computeFailure(needles, plen);


        int j = 0;

        for (int i = 0; i < dlen; i++) {
            while (j > 0 && needles[j] != haystack[i]) {
                j = failure[j - 1];
            }
            if (needles[j] == haystack[i]) {
                j++;
            }
            if (j == plen) {
                return i - plen + 1;
            }
        }
        return -1;
    }

    /**
     * Computes the failure function using a boot-strapping process,
     * where the pattern is matched against itself.
     *
     * @param pattern A byte array to compage against itself.
     * @param plen The length of the array, previously-computed and stored.
     *             (This is a very minor performance optimization)
     *
     * @return The KPM "failure" string for the pattern.
     */
    private static int[] computeFailure(byte[] pattern, final int plen) {
        int[] failure = new int[plen];

        int j = 0;
        for (int i = 1; i < plen; i++) {
            while (j>0 && pattern[j] != pattern[i]) {
                j = failure[j - 1];
            }
            if (pattern[j] == pattern[i]) {
                j++;
            }
            failure[i] = j;
        }

        return failure;
    }
}