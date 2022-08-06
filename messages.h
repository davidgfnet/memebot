
// Bot messages, hardcoded here by language
// for efficiency and low-dependency reasons.

#define MSG_START   0
#define MSG_DOWN    1

static const char *messages[] = {
  // [0] Welcome message, on /start
  "Hello there! I'm Meme Make Bot!\n"
  "You guessed it right, I make memes! To create a meme, use this bot as an _inline_ bot, that is, "
  "call me by writing @mememakebot in any other conversation/chat (not here for instance).\n"
  "As an example, if you want to create a panda meme that says hello you may write:\n"
  "\n"
  "@mememakebot panda,hello!\n"
  "\n"
  "Then, do *not* hit Send button, but wait for images to appear as a search box, you might "
  "pick the panda you love the most and select that picture by clicking/tapping on it.\n"
  "The meme will be sent with the picture and the Hello text\n",
  // [1] Maintenance message
  "Sorry! The bot is under maintenance, please check back in a bit 😅",
};

