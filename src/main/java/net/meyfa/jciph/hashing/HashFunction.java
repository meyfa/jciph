package net.meyfa.jciph.hashing;

/**
 * Abstract superclass for hash functions.
 */
public abstract class HashFunction
{
    /**
     * Hashes the given array of bytes using this hash function and returns the
     * computed result.
     *
     * @param message The message to hash.
     * @return The hash, as a byte array.
     */
    public abstract byte[] hash(byte[] message);
}
