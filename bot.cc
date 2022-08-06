
// MemeBot, an inline Telegram bot that allows user to create memes and
// send them as image messages.

// Copyright David Guillen Fandos 2020 <david@davidgf.net>

#include <thread>
#include <mutex>
#include <regex>
#include <fstream>
#include <fcgio.h>
#include <signal.h>
#include <nlohmann/json.hpp>
#include <libconfig.h>
#include <future>
#include <openssl/sha.h>

#include "util.h"
#include "cqueue.h"
#include "httpclient.h"
#include "messages.h"
#include "logger.h"
#include "lrucache.h"

#define SEARCH_URL "https://imgflip.com/memesearch"
#define MAX_REQ_SIZE  (4*1024)

#define RET_ERR(x) { std::cerr << x << std::endl; return 1; }

typedef struct {
	uint64_t tid;
	float aspect;
	std::string url;
} t_meme_template;

typedef lru11::Cache<std::string, std::vector<t_meme_template>> LRUCache;
using nlohmann::json;

const std::regex memeimg("<a[^>]+href=\"/meme/([0-9]+)/[^\"]+\"[^>]*>[.\\n\\r]*?<img[^>]+style=\"[^\"]*width:([0-9\\.]+)px[^\"]*height:([0-9\\.]+)px[^\"]*\"[^>]+src=\"([^\"]+)\"[^>]*>", std::regex_constants::icase | std::regex_constants::ECMAScript | std::regex_constants::optimize);
const std::regex memeuri(".*/meme/([0-9]+)/(.*)", std::regex_constants::optimize);

unsigned maintenance = 0;   // Maintenance mode enabled
unsigned nthreads = 4;      // Number of threads to use
std::string telegram_url;   // URL to use to query Telegram servers
std::string base_url;       // Base URL to create meme image URLs
std::string imgflip_user;   // API username
std::string imgflip_pwd;    // API password

static std::string escapenl(std::string expr) {
	static std::regex reg("\\n");
	return std::regex_replace(expr, reg, "\\n");
}

static std::string basichash(std::string c) {
	char digest[32];
	SHA256((uint8_t*)c.c_str(), c.size(), (uint8_t*)digest);
	for (unsigned i = 0; i < 32; i++)
		digest[i] = '0' + (digest[i] & 31);
	return std::string(digest, 32);
}

class TelegramBotServer {
private:
	// HTTP client, has its own thread to process requests.
	HttpClient client;

	// Thread to spawn
	std::thread cthread;

	// Shared queue
	ConcurrentQueue<std::unique_ptr<FCGX_Request>> *rq;

	// Signal end of workers
	bool end;

	// Logging facilities
	Logger *log;

	// Search template caches
	LRUCache *search_cache;

	std::vector<t_meme_template> fetchMemeURLs(const std::string &memsearch) {
		auto fret = client.get(SEARCH_URL, {{"q", memsearch}});
		if (!fret.first)
			return {};
		std::vector<t_meme_template> ret;
		for (auto it = std::sregex_iterator(fret.second.begin(), fret.second.end(), memeimg);
				  it != std::sregex_iterator(); ++it) {
			std::smatch m = *it;
			std::string iurl = m.str(4);
			uint64_t memetid = atoll(m.str(1).c_str());
			double imwidth = atof(m.str(2).c_str());
			double imheight = atof(m.str(3).c_str());
			if (iurl.substr(0, 4) != "http")
				iurl = "https:" + iurl;
			ret.push_back(t_meme_template{
				memetid, (float)(imwidth / imheight), iurl});
		}
		return ret;
	}

	std::vector<t_meme_template> getMemeURLs(const std::string &memsearch) {
		std::vector<t_meme_template> ret;
		if (!search_cache->tryGet(memsearch, ret)) {
			ret = fetchMemeURLs(memsearch);
			search_cache->insert(memsearch, ret);
		}
		return ret;
	}

	std::string process_req(const json & req) {
		if (req.count("message") && req["message"].count("chat") && req["message"]["chat"].count("id")) {
			uint64_t u = req["message"]["chat"]["id"];

			// Check maintenance and reply earlier
			if (maintenance)
				return reply_message(u, messages[MSG_DOWN]);

			return reply_message(u, messages[MSG_START]);
		}
		else if (req.count("inline_query") && req["inline_query"].count("query") &&
		    req["inline_query"].count("id")) {
			// This is an inline message for a meme request.
			const std::string qt = req["inline_query"]["query"];
			auto p = qt.find(",");
			const std::string meme = p == std::string::npos ? qt : qt.substr(0, p);
			const std::string capt = p == std::string::npos ? "" : qt.substr(p+1);

			// Check maintenance and reply earlier
			if (maintenance)
				return reply_inline_query(req["inline_query"]["id"], json::array());

			// Get all memes
			log->log("INFO Got a request for meme: " + meme);
			auto memelist = getMemeURLs(meme);

			json results;
			for (const auto & m : memelist) {
				const std::string purl = base_url + std::to_string(m.tid) +
					"/" + HttpClient::urlescape(capt);
				json e = {
					{"type", "photo"},
					{"id", basichash(purl)},   // Use a unique id (caption + template)
					{"photo_url", purl},
					{"thumb_url", m.url},
					{"photo_width", 300},
					{"photo_height", (unsigned)(300 / m.aspect)},
				};
				results.push_back(e);
			}
			log->log("INFO Got " + std::to_string(results.size()) + " candidates");

			return reply_inline_query(req["inline_query"]["id"], results);
		}
		return {};
	}

	std::string reply_message(long userid, std::string msg, std::string rmarkup = "") {
		log->log("INFO Replying user fast " + std::to_string(userid) + ": " + escapenl(msg));
		json r = {
			{"method", "sendMessage"},
			{"chat_id", userid},
			{"text", msg},
			{"parse_mode", "Markdown"},
			{"reply_markup", rmarkup},
		};
		return r.dump();
	}

	std::string reply_inline_query(std::string queryid, const json &results) {
		json r = {
			{"method", "answerInlineQuery"},
			{"inline_query_id", queryid},
			{"cache_time", 3600*24},    // Cache the thing for a while since it shouldn't change much
			{"results", results},
		};
		return r.dump();
	}

public:
	TelegramBotServer(
		Logger *log, ConcurrentQueue<std::unique_ptr<FCGX_Request>> *rq,
		LRUCache *search_cache)
	: rq(rq), end(false), log(log), search_cache(search_cache)
	{
		// Use work() as thread entry point
		cthread = std::thread(&TelegramBotServer::work, this);
	}

	~TelegramBotServer() {
		// Now join the thread
		cthread.join();
	}

	// Receives requests and processes them by replying via a side http call.
	void work() {
		std::unique_ptr<FCGX_Request> req;
		while (rq->pop(&req)) {
			// Get streams to write
			fcgi_streambuf reqout(req->out);
			fcgi_streambuf reqin(req->in);
			std::iostream obuf(&reqout);
			std::iostream ibuf(&reqin);

			long bsize = atol(FCGX_GetParam("CONTENT_LENGTH", req->envp));
			if (bsize > 0 && bsize < MAX_REQ_SIZE) {
				// Read body and parse JSON
				char body[MAX_REQ_SIZE+1];
				ibuf.read(body, bsize);
				body[bsize] = 0;

				log->log("INFO Got json request " + escapenl(body));
				std::string immresp;
				auto req = json::parse(body, nullptr, false);
				if (req.is_discarded())
					log->log("ERROR Parsing json " + escapenl(body));
				else
					immresp = process_req(req);

				// Respond with an immediate update JSON encoded too
				obuf << "HTTP/1.1 200 OK\r\n"
				     << "Content-Type: application/json\r\n"
				     << "Content-Length: " << immresp.size() << "\r\n\r\n"
				     << immresp;
			}
			else {
				// It might be the meme generation endpoint, parse the GET URI
				std::string uri = FCGX_GetParam("REQUEST_URI", req->envp);
				std::smatch m;
				std::string imgbytes;
				if (std::regex_match(uri, m, memeuri)) {
					std::string tid = m.str(1);
					std::string caption = HttpClient::urlunescape(m.str(2));
					auto s2 = caption.find("/");
					std::string text0 = s2 != std::string::npos ? caption.substr(0, s2) : "";
					std::string text1 = s2 != std::string::npos ? caption.substr(s2 + 1) : caption;
					log->log("INFO Got an image request for template " + tid + " with text " + escapenl(caption));
					std::shared_ptr<std::string> postresp(new std::string());
					std::promise<std::string> resprom;
					std::future<std::string> futprom = resprom.get_future();
					client.doPOST("https://api.imgflip.com/caption_image", {
						{"template_id", tid},
						{"username", imgflip_user},
						{"password", imgflip_pwd},
						{"text1", text1},
						{"text0", text0}},
						{},
						[postresp] (std::string resp) -> bool {
							// Accumulate the response and process it at the end.
							*postresp += resp;
							return postresp->size() < 128*1024;
						},
						[this, postresp, &resprom] (bool ok) {
							if (ok) {
								// Get the response json that contains the URL of the generated image.
								std::string memimgurl;
								auto iresp = json::parse(*postresp, nullptr, false);
								if (iresp.is_discarded())
									log->log("ERROR Parsing response json " + escapenl(*postresp));
								else if (iresp.count("data") && iresp["data"].count("url"))
									memimgurl = iresp["data"]["url"];
								resprom.set_value(memimgurl);
							}
						});

					// Fetch the image from the URL we got, if we got any at all
					std::string imgurl = futprom.get();
					if (!imgurl.empty()) {
						auto imgresp = client.get(imgurl, {});
						imgbytes = imgresp.second;
						log->log("INFO Fetched image " + imgurl + " returned " + std::to_string(imgbytes.size()));
					}
				}
				if (imgbytes.empty())
					obuf << "HTTP/1.1 500 Internal Server Error\r\n\r\n";
				else
					obuf << "HTTP/1.1 200 OK\r\n"
						 << "Content-Type: image/jpeg\r\n"
						 << "Content-Length: " << imgbytes.size() << "\r\n\r\n"
						 << imgbytes;
			}

			FCGX_Finish_r(req.get());
			req.reset();
		}
	}
};

bool serving = true;
void sighandler(int) {
	std::cerr << "Signal caught" << std::endl;
	// Just tweak a couple of vars really
	serving = false;
	// Ask for CGI lib shutdown
	FCGX_ShutdownPending();
	// Close stdin so we stop accepting
	close(0);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " file.conf" << std::endl;
		return 1;
	}

	config_t cfg;
	config_init(&cfg);

	if (!config_read_file(&cfg, argv[1]))
		RET_ERR("Error reading config file");

	// Read config vars
	const char *apikey, *logfile, *base_url_, *imgflip_user_, *imgflip_pwd_;
	config_lookup_int(&cfg, "maintenance", (int*)&maintenance);
	config_lookup_int(&cfg, "nthreads", (int*)&nthreads);

	if (!config_lookup_string(&cfg, "logs", &logfile))
		logfile = "/tmp/";
	if (!config_lookup_string(&cfg, "tg-apikey", &apikey))
		RET_ERR("Telegram API key is required in config file var 'apikey'");
	if (!config_lookup_string(&cfg, "base_url", &base_url_))
		RET_ERR("Base URL for the bot is required in config file var 'base_url'");
	if (!config_lookup_string(&cfg, "imgflip_username", &imgflip_user_))
		RET_ERR("ImgFlip username is required in the config file var 'imgflip_username'");
	if (!config_lookup_string(&cfg, "imgflip_password", &imgflip_pwd_))
		RET_ERR("ImgFlip password is required in the config file var 'imgflip_password'");

	telegram_url = "https://api.telegram.org/bot" + HttpClient::urlescape(apikey);
	base_url = base_url_;
	imgflip_user = imgflip_user_;
	imgflip_pwd = imgflip_pwd_;

	// Start FastCGI interface
	FCGX_Init();

	// Signal handling
	signal(SIGINT, sighandler); 
	signal(SIGTERM, sighandler);
	signal(SIGPIPE, SIG_IGN);

	// Start worker threads for this
	if (!nthreads)
		nthreads = 1;

	LRUCache search_cache(1024, 128);
	Logger mainlogger(logfile);
	ConcurrentQueue<std::unique_ptr<FCGX_Request>> reqqueue;
	TelegramBotServer *workers[nthreads];
	for (unsigned i = 0; i < nthreads; i++)
		workers[i] = new TelegramBotServer(&mainlogger, &reqqueue, &search_cache);

	std::cerr << "All workers up, serving until SIGINT/SIGTERM" << std::endl;

	// Now keep ingesting incoming requests, we do this in the main
	// thread since threads are much slower, unlikely to be a bottleneck.
	while (serving) {
		std::unique_ptr<FCGX_Request> request(new FCGX_Request());
		FCGX_InitRequest(request.get(), 0, 0);

		if (FCGX_Accept_r(request.get()) >= 0)
			// Get a worker that's free and queue it there
			reqqueue.push(std::move(request));
	}

	std::cerr << "Signal caught! Starting shutdown" << std::endl;
	reqqueue.close();

	// Just go ahead and delete workers
	for (unsigned i = 0; i < nthreads; i++)
		delete workers[i];

	std::cerr << "All clear, service is down" << std::endl;
}


