Centralized registration of yara rules for programmatic access to a corpus of rules from various python packages.

1. Install with `pip install yara-registry`
	* This does not come with yara or yara-x, so you can install whatever version you want or only install the engine of choice.  Version compatibility depends on their API not chaning, so not all versions are supported.
	* Install bundled yara-python with `pip install yara-registry[yara]`, yara-x with `pip install yara-registry[yara-x]`, or both with `pip install yara-registry[yara,yara-x]`
2. Register your rules
	a. For a python package: register yara registry as an entry point for your project rules
		Example:

		[project.entry-points."yara_registry.rules"]
		rules = "<your_project>.path.to.rules"
   b. Register non-python projects through the registry CLI
	   Example:

		yara_registry add --namespace <name of project or source> --path <path.to.rules>
	When registering rules with the CLI the namespace should be unique with both python package names and CLI rules.  For example if have a python package with rules named "my_yara_rules" do not add rules with the CLI using "--namespace my_yara_rules".
3. Verify rule installation using `yara_registry list` or `yara_registry list --source <namespace/package name>`
4. Access rules programmatically
	* Access all rules directly through `yara_registry.yara.YaraCorpus` or `yara_registry.yara_x.YaraXCorpus`
	* Access specific sources through `Corpus.get_source(<source_name>)`
	* Match against rules using `Corpus.match`
