import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import ReactHtmlParser from 'react-html-parser';

const Blogs = () => {
    const [blogs, setBlogs] = useState([]);
    const [fetchSingleUser, setFetchSingleUser] = useState([]);
    const [allBlogsPerPage] = useState(6);
    const [currentPage, setCurrentPage] = useState(1);
    const fetchBlogs = () => {
        fetch('http://localhost:5000/newBlogs')
            .then(res => res.json())
            .then(data => {
                setBlogs(data);
                console.log(data);
            })
    }
    const fetchUser = () => {
        fetch('http://localhost:5000/users')
            .then(res => res.json())
            .then(data => {
                const blogWriter = blogs.blogPostedByEmail === data.email
                setFetchSingleUser(blogWriter);
                console.log(blogWriter);
            })
    }
    useEffect(() => {
        fetchBlogs();
        fetchUser();
    })


    const indexOfLastFlat = currentPage * allBlogsPerPage;
    const indexOfFirstFlat = indexOfLastFlat - allBlogsPerPage;
    const currentBlogs = blogs.slice(indexOfFirstFlat, indexOfLastFlat);

    // Change page
    const paginate = (pageNumber) => setCurrentPage(pageNumber);
    return (
        <div className="lg:w-3/4 w-11/12 mx-auto my-8">
            <div className="grid grid-cols-3 gap-6">
                {
                    currentBlogs.map(singleBlog => <div className="custom-shadow p-6 rounded-md" key={singleBlog._id}>
                        <div className="pb-3 flex justify-between">
                            <div>
                                <h4 className="text-3xl font-semibold">{singleBlog.blogTitle}</h4>
                                <p>
                                    by{" "}
                                    <Link to={`/user/${singleBlog.blogPostedByName}/${fetchSingleUser._id}`}>
                                        <span className="text-[#1d9cb5] capitalize font-semibold cursor-pointer">
                                            {singleBlog.blogPostedByName}
                                        </span>
                                    </Link>
                                </p>
                            </div>
                            <div className="badge badge-primary bg-[#1d9cb5] border-none text-white">{singleBlog.blogPostDate}</div>
                        </div>
                        <p>
                            {ReactHtmlParser(singleBlog.blogBody.substring(0, 120))}...
                            <Link to={`/blogDetails/${singleBlog.blogTitle ? singleBlog.blogTitle : 'undefinedTitle'}/${singleBlog._id}`} className="text-[#1d9cb5]" >
                                see more
                            </Link>
                        </p>

                    </div>)
                }
            </div>
            {/* for pagination */}
            <div className=" flex flex-wrap justify-center mb-10 mt-5">
                <button
                    className="join-item btn btn-outline mr-2"
                    onClick={() => paginate(currentPage - 1)}
                    disabled={currentPage === 1}
                >
                    &larr; Previous page
                </button>
                {Array.from(
                    { length: Math.ceil(blogs.length / allBlogsPerPage) },
                    (_, i) => (
                        <button
                            key={i}
                            onClick={() => paginate(i + 1)}
                            className={`join-item btn btn-outline mr-2 ${currentPage === i + 1 ? "bg-green-400 text-white" : ""
                                }`}
                        >
                            {i + 1}
                        </button>
                    )
                )}
                <button
                    className="join-item btn btn-outline mr-2"
                    onClick={() => paginate(currentPage + 1)}
                    disabled={currentPage === Math.ceil(blogs.length / allBlogsPerPage)}
                >
                    Next &rarr;
                </button>
            </div>
        </div>
    );
};

export default Blogs;