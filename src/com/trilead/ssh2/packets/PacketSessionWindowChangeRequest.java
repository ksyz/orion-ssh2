package com.trilead.ssh2.packets;


/**
 * PacketSessionWindowChangeRequest.
 * 
 * @author Juraj Bednar, juraj.bednar@digmia.com
 * @version $Id: PacketSessionWindowChangeRequest.java,v 1.0 $
 */
public class PacketSessionWindowChangeRequest
{
	byte[] payload;

	public int recipientChannelID;
	public boolean wantReply;
	public String term;
	public int character_width;
	public int character_height;
	public int pixel_width;
	public int pixel_height;
	public byte[] terminal_modes;

	public PacketSessionWindowChangeRequest(int recipientChannelID, boolean wantReply,
			int character_width, int character_height, int pixel_width, int pixel_height)
	{
		this.recipientChannelID = recipientChannelID;
		this.wantReply = wantReply;
		this.character_width = character_width;
		this.character_height = character_height;
		this.pixel_width = pixel_width;
		this.pixel_height = pixel_height;
	}

	public byte[] getPayload()
	{
		if (payload == null)
		{
			TypesWriter tw = new TypesWriter();
			tw.writeByte(Packets.SSH_MSG_CHANNEL_REQUEST);
			tw.writeUINT32(recipientChannelID);
			tw.writeString("window-change");
			tw.writeBoolean(wantReply);
			tw.writeUINT32(character_width);
			tw.writeUINT32(character_height);
			tw.writeUINT32(pixel_width);
			tw.writeUINT32(pixel_height);

			payload = tw.getBytes();
		}
		return payload;
	}
}
