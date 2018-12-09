#ifndef AFL_CAPTURE_STATS_H
#define AFL_CAPTURE_STATS_H

void write_stats_file(double bitmap_cvg, double stability, double eps);
void show_stats(void);
void show_init_stats(void);

#endif /* ! AFL_CAPTURE_STATS_H */
