package jciph;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import net.meyfa.jciph.hashing.Sha512;


public class Sha512Test
{
    private static class MockSha512 extends Sha512
    {
        private int blocksProcessed = 0;

        // exists so that we can access it here
        @Override
        protected byte[] pad(byte[] message, int length)
        {
            return super.pad(message, length);
        }

        @Override
        protected void processBlock(byte[] block, int off)
        {
            super.processBlock(block, off);
            ++blocksProcessed;
        }
    }

    // hash(byte[])

    @Test
    public void testHashEmpty()
    {
        byte[] b = {};
        byte[] expected = DatatypeConverter.parseHexBinary(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        assertArrayEquals(expected, new Sha512().hash(b));
    }

    @Test
    public void testHashRegular()
    {
        byte[] b = "Hello world!".getBytes(StandardCharsets.US_ASCII);
        byte[] expected = DatatypeConverter.parseHexBinary(
                "f6cde2a0f819314cdde55fc227d8d7dae3d28cc556222a0a8ad66d91ccad4aad6094f517a2182360c9aacf6a3dc323162cb6fd8cdffedb0fe038f55e85ffb5b6");

        assertArrayEquals(expected, new Sha512().hash(b));
    }

    @Test
    public void testHashLong()
    {
        byte[] b = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
                + "Proin pulvinar turpis purus, sit amet dapibus magna commodo "
                + "quis metus.").getBytes(StandardCharsets.US_ASCII);
        byte[] expected = DatatypeConverter.parseHexBinary(
                "de94877cc9711605dcdc09d85bd3080f74398d5e1ad8f0dcd1726c54ac93f2b4b781c3f56de1fbc725ac261a2c09d1d5bb24d0afa7449e4ffe4b2a7e6d09f40d");

        assertArrayEquals(expected, new Sha512().hash(b));
    }

    @Test
    public void testHashRawBytes()
    {
        byte[] b = new byte[256];
        for (int i = 0; i < b.length; ++i) {
            b[i] = (byte) i;
        }

        byte[] expected = DatatypeConverter.parseHexBinary(
                "1e7b80bc8edc552c8feeb2780e111477e5bc70465fac1a77b29b35980c3f0ce4a036a6c9462036824bd56801e62af7e9feba5c22ed8a5af877bf7de117dcac6d");

        assertArrayEquals(expected, new Sha512().hash(b));
    }

    @Test
    public void testHashReuse()
    {
        Sha512 instance = new Sha512();

        byte[] b0 = "hello".getBytes(StandardCharsets.US_ASCII);
        byte[] exp0 = DatatypeConverter.parseHexBinary(
                "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043");

        byte[] b1 = "world".getBytes(StandardCharsets.US_ASCII);
        byte[] exp1 = DatatypeConverter.parseHexBinary(
                "11853df40f4b2b919d3815f64792e58d08663767a494bcbb38c0b2389d9140bbb170281b4a847be7757bde12c9cd0054ce3652d0ad3a1a0c92babb69798246ee");

        assertArrayEquals(exp0, instance.hash(b0));
        assertArrayEquals(exp1, instance.hash(b1));
    }

    // finish()

    @Test
    public void testFinishCallsProcessBlockTwiceIfNeeded()
    {
        MockSha512 mock = new MockSha512();
        mock.hash(new byte[111]);

        assertEquals(2, mock.blocksProcessed);
    }

    // protected pad(byte[], int)

    @Test
    public void testPaddedLengthDivisibleByBlockSize()
    {
        byte[] b = { 0, 1, 2, 3, 0 };

        byte[] padded = new MockSha512().pad(b, b.length);

        assertTrue(padded.length % 128 == 0);
    }

    @Test
    public void testPaddedMessageHas1Bit()
    {
        byte[] b = new byte[128];

        byte[] padded = new MockSha512().pad(b, b.length);

        assertEquals((byte) 0b1000_0000, padded[b.length]);
    }

    @Test
    public void testPaddingAllZero()
    {
        byte[] b = { 1, 1, 1, 1, 1, 1, 1, };

        byte[] padded = new MockSha512().pad(b, b.length);

        for (int i = b.length + 1; i < padded.length - 16; ++i) {
            assertEquals("byte " + i + " not 0", 0, padded[i]);
        }
    }

    @Test
    public void testPaddingHasTotalSize()
    {
        MockSha512 mock = new MockSha512();
        mock.digest(new byte[128]);
        mock.digest(new byte[128]);
        mock.digest(new byte[64]);

        ByteBuffer buf = ByteBuffer.wrap(mock.pad(new byte[0], 0));

        buf.position(buf.capacity() - 16);
        byte[] dst = new byte[16];
        buf.get(dst);

        assertEquals((128 + 128) * Byte.SIZE, new BigInteger(dst).intValue());
    }
}
