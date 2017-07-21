package de.jangobrick.jciph.hashing;

import java.nio.ByteBuffer;


/**
 * Abstract superclass for hash functions that process their messages as
 * fixed-size blocks.
 *
 * <p>
 * Call the {@link #digest(byte[])} method to add data to be hashed. Then, call
 * {@link #finish()} to obtain the result. Optionally call {@link #reset()} as a
 * first step to ensure no state was left behind by a previous operation (called
 * automatically after {@code finish()} concludes).
 */
public abstract class BlockHashFunction extends HashFunction
{
    private final int blockSize;
    private final ByteBuffer blockBuffer;

    /**
     * @param blockSize The block size, in bytes, that this function uses.
     */
    public BlockHashFunction(int blockSize)
    {
        this.blockSize = blockSize;
        this.blockBuffer = ByteBuffer.allocate(blockSize);
    }

    @Override
    public byte[] hash(byte[] message)
    {
        reset();
        digest(message);

        return finish();
    }

    /**
     * Clear this function's state so that computation can begin anew.
     */
    public void reset()
    {
        blockBuffer.clear();
    }

    /**
     * Add data to be hashed. The array does not have to be of any specific
     * length and this method can be called many times.
     *
     * @param partialMessage The message data to add.
     */
    public void digest(byte[] partialMessage)
    {
        int consumed = 0;
        while (consumed < partialMessage.length) {

            int max = Math.min(blockSize, partialMessage.length - consumed);

            blockBuffer.put(partialMessage, consumed, max);
            consumed += max;

            if (!blockBuffer.hasRemaining()) {
                processBlock(blockBuffer.array());
                blockBuffer.clear();
            }

        }
    }

    /**
     * Finalizes the hashing process with the data that was collected until now.
     *
     * @return The hash, as a byte array.
     */
    public byte[] finish()
    {
        byte[] result = finish(blockBuffer.array(), blockBuffer.position());
        reset();

        return result;
    }

    /**
     * When enough bytes have been collected inside {@link #digest(byte[])},
     * this method is called with the full block. The array has a length equal
     * to the block size.
     *
     * @param block
     */
    protected abstract void processBlock(byte[] block);

    /**
     * Called by the public {@link #finish()} method with the remaining, not yet
     * processed bytes. The amount of unprocessed bytes in the given array,
     * starting at index 0, is given through the {@code length} parameter.
     *
     * @param remainder Array containing the unprocessed bytes.
     * @param length The number of unprocessed bytes in the array.
     * @return The computed hash.
     */
    protected abstract byte[] finish(byte[] remainder, int length);
}
