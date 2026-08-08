.PHONY: app bl clean size_report size_report_files

all: bl app ota

bl:
	@$(MAKE) -C bootloader/

app:
	@$(MAKE) -C application/

ota:
	@$(MAKE) -C application/ full ota

clean:
	@rm -rf _build/

size_report:
	@$(MAKE) -C application/ size_report

size_report_files:
	@$(MAKE) -C application/ size_report_files
