package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/carsondecker/chirpy/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}

	apiCfg := &apiConfig{
		db: database.New(db),
	}

	mux := http.NewServeMux()
	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	mux.HandleFunc("GET /api/healthz", healthzHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)
	mux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)
	server.ListenAndServe()
}

func healthzHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(200)
	html := fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())
	w.Write([]byte(html))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	cfg.fileserverHits.Store(0)
}

func validateChirpHandler(w http.ResponseWriter, req *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}

	params := parameters{}

	w.Header().Set("Content-Type", "application/json")

	decoder := json.NewDecoder(req.Body)
	defer req.Body.Close()
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, "Failed to unmarshal json")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}

	type resSuccess struct {
		CleanedBody string `json:"cleaned_body"`
	}
	respondWithJSON(w, 200, resSuccess{CleanedBody: cleanMessage(params.Body)})
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, req)
	})
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type resError struct {
		Error string `json:"error"`
	}
	respondWithJSON(w, code, resError{Error: msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	w.Write(data)
}

func cleanMessage(msg string) string {
	profanities := []string{
		"sharbert",
		"kerfuffle",
		"fornax",
	}

	splitMsg := strings.Split(msg, " ")
	for i, word := range splitMsg {
		for _, profanity := range profanities {
			if strings.ToLower(word) == profanity {
				splitMsg[i] = "****"
				break
			}
		}
	}

	return strings.Join(splitMsg, " ")
}
