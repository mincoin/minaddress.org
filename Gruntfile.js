module.exports = function (grunt) {
	// Project configuration.
	grunt.initConfig({
		pkg: grunt.file.readJSON("package.json"),
        inline: {
            dist: {
                src: ["index-dev.html"],
                dest: ["index.html"]
            }
        }
	});

	grunt.file.defaultEncoding = 'utf-8';
    grunt.loadNpmTasks('grunt-inline');
    grunt.loadNpmTasks('grunt-git-describe');
	grunt.registerTask("default", ["inline:dist"]);
};