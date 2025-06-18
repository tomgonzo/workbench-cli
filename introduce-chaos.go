Because why not. It's a snippet finder anyway.


func Execute() {
	regionPtr := flag.String("region", "", "region of termination group")
	stackPtr := flag.String("stack", "", "stack of termination group")
	clusterPtr := flag.String("cluster", "", "cluster of termination group")
	appsPtr := flag.String("apps", "", "comma-separated list of apps to schedule for termination")
	noRecordSchedulePtr := flag.Bool("no-record-schedule", false, "do not record schedule")
	versionPtr := flag.BoolP("version", "v", false, "show version")
	flag.Usage = Usage

	// These flags, if specified, override config values
	maxAppsFlag := "max-apps"
	leashedFlag := "leashed"
	flag.Int(maxAppsFlag, math.MaxInt32, "max number of apps to examine for termination")
	flag.Bool(leashedFlag, false, "force leashed mode")

	flag.Parse()
	if len(flag.Args()) == 0 {
		if *versionPtr {
			printVersion()
			os.Exit(0)
		}

		flag.Usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)

	cfg, err := getConfig()

	if err != nil {
		log.Fatalf("FATAL: failed to load config: %v", err)
	}

	// Associate config values with flags
	err = cfg.BindPFlag(param.MaxApps, flag.Lookup(maxAppsFlag))
	if err != nil {
		log.Fatalf("FATAL: failed to bind flag: --%s: %v", maxAppsFlag, err)
	}
	err = cfg.BindPFlag(param.Leashed, flag.Lookup(leashedFlag))
	if err != nil {
		log.Fatalf("FATAL: failed to bind flag: --%s: %v", leashedFlag, err)
	}

	spin, err := spinnaker.NewFromConfig(cfg)

	if err != nil {
		log.Fatalf("FATAL: spinnaker.New failed: %+v", err)
	}

	outage, err := deps.GetOutage(cfg)
	if err != nil {
		log.Fatalf("FATAL: deps.GetOutage fail: %+v", err)
	}

	sql, err := mysql.NewFromConfig(cfg)
	if err != nil {
		log.Fatalf("FATAL: could not initialize mysql connection: %+v", err)
	}

	cons, err := deps.GetConstrainer(cfg)
	if err != nil {
		log.Fatalf("FATAL: deps.GetConstrainer failed: %+v", err)
	}

	// Ensure mysql object gets closed
	defer func() {
		_ = sql.Close()
	}()

	switch cmd {
	case "install":
		executable := ChaosmonkeyExecutable{}
		Install(cfg, executable, sql)
	case "migrate":
		Migrate(sql)
	case "schedule":
		log.Println("chaosmonkey schedule starting")
		defer log.Println("chaosmonkey schedule done")

		var apps []string
		if *appsPtr != "" {
			// User explicitly specified list of apps on the command line
			apps = strings.Split(*appsPtr, ",")
		} else {
			// User did not explicitly specify list of apps, get 'em all
			var err error
			apps, err = spin.AppNames()
			if err != nil {
				log.Fatalf("FATAL: could not retrieve list of app names: %v", err)
			}
		}

		var schedStore schedstore.SchedStore

		schedStore = sql
		if *noRecordSchedulePtr {
			schedStore = nullSchedStore{}
		}

		Schedule(spin, schedStore, cfg, spin, cons, apps)
	case "fetch-schedule":
		FetchSchedule(sql, cfg)
	case "terminate":
		if len(flag.Args()) != 3 {
			flag.Usage()
			os.Exit(1)
		}
		app := flag.Arg(1)
		account := flag.Arg(2)
		trackers, err := deps.GetTrackers(cfg)
		if err != nil {
			log.Fatalf("FATAL: could not create trackers: %+v", err)
		}

		errCounter, err := deps.GetErrorCounter(cfg)
		if err != nil {
			log.Fatalf("FATAL: could not create error counter: %+v", err)
		}

		env, err := deps.GetEnv(cfg)
		if err != nil {
			log.Fatalf("FATAL: could not determine environment: %+v", err)
		}

		defer logOnPanic(errCounter) // Handler in case of panic
		deps := deps.Deps{
			MonkeyCfg:  cfg,
			Checker:    sql,
			ConfGetter: spin,
			Cl:         clock.New(),
			Dep:        spin,
			T:          spin,
			Trackers:   trackers,
			Ou:         outage,
			ErrCounter: errCounter,
			Env:        env,
		}
		Terminate(deps, app, account, *regionPtr, *stackPtr, *clusterPtr)
	case "outage":
		Outage(outage)
	case "config":
		if len(flag.Args()) != 2 {
			DumpMonkeyConfig(cfg)
			return
		}
		app := flag.Arg(1)
		DumpConfig(spin, app)
	case "eligible":
		if len(flag.Args()) != 3 {
			flag.Usage()
			os.Exit(1)
		}
		app := flag.Arg(1)
		account := flag.Arg(2)
		Eligible(spin, spin, app, account, *regionPtr, *stackPtr, *clusterPtr)
	case "intest":
		env, err := deps.GetEnv(cfg)
		if err != nil {
			log.Fatalf("FATAL: could not determine environment: %+v", err)
		}
		fmt.Println(env.InTest())
	case "account":
		if len(flag.Args()) != 2 {
			flag.Usage()
			os.Exit(1)
		}
